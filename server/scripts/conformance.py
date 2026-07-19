"""AVP 1.0 conformance suite — run against any live vault.

Usage:
    python server/scripts/conformance.py --url http://localhost:8000 --principal-token ptk_...

Creates its own agent and credential (service "openai", fake key), exercises
the protocol per docs/AVP_v1_SPEC.md §12, and revokes what it created.
Exit code 0 = conformant, 1 = failures.
"""
from __future__ import annotations

import argparse
import secrets
import sys

import httpx

PASSES: list = []
FAILS: list = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASSES if cond else FAILS).append(name)
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {name}" + (f" — {detail}" if detail and not cond else ""))


def is_error_envelope(body) -> bool:
    return (isinstance(body, dict)
            and body.get("avp_version") == "1.0"
            and body.get("type") == "error"
            and isinstance(body.get("code"), str)
            and isinstance(body.get("message"), str))


def envelope_of(resp: httpx.Response):
    """Return the AVP error envelope from a response, unwrapping HTTP detail."""
    try:
        body = resp.json()
    except Exception:
        return None
    if is_error_envelope(body):
        return body
    detail = body.get("detail") if isinstance(body, dict) else None
    return detail if is_error_envelope(detail) else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--principal-token", required=True)
    args = ap.parse_args()

    base = args.url.rstrip("/")
    c = httpx.Client(timeout=30.0)
    ptk = {"Authorization": f"Bearer {args.principal_token}"}

    run = secrets.token_hex(4)
    agent_id = f"conf_{run}"
    label = f"conf_{run}"
    cap = {"service": "openai", "scopes": ["chat"], "environment": "prod", "resource": label, "mode": "both"}

    # -- fixtures ----------------------------------------------------------
    r = c.post(f"{base}/agents", headers=ptk, json={
        "agent_id": agent_id, "name": "Conformance", "description": None,
        "default_policy": {"allowed_capabilities": [cap], "max_session_seconds": 600}})
    if r.status_code != 200:
        print(f"cannot create fixture agent (HTTP {r.status_code}): {r.text}")
        return 1
    c.post(f"{base}/secrets", headers=ptk, json={
        "service_name": "openai", "label": label, "environment": "prod",
        "data": {"api_key": "sk-conformance-fake"}, "meta": {}})
    agt = c.post(f"{base}/agents/{agent_id}/tokens", headers=ptk, json={}).json()["token"]
    ah = {"Authorization": f"Bearer {agt}"}

    def hello(caps, aid=agent_id):
        return c.post(f"{base}/avp/agent_hello", headers=ah, json={
            "avp_version": "1.0", "type": "agent_hello", "agent_id": aid,
            "agent_version": "0.0.0", "runtime": "conformance", "metadata": {},
            "requested_capabilities": caps})

    # -- 1. session establishment + envelope (§6, §7.1) --------------------
    r = hello([cap])
    ok = r.status_code == 200
    sess = r.json() if ok else {}
    check("7.1 session established", ok, f"HTTP {r.status_code}: {r.text[:200]}")
    check("6   agent_session envelope", ok
          and sess.get("avp_version") == "1.0" and sess.get("type") == "agent_session"
          and isinstance(sess.get("session_token"), str) and isinstance(sess.get("session_id"), str))
    check("7.1 capability handle issued", isinstance(sess.get("capability_handles", {}).get("openai"), str))
    granted = sess.get("granted_capabilities") or []
    check("5.1 grant not broader than template",
          all(set(g["scopes"]) <= {"chat"} and g["resource"] == label for g in granted) and granted != [])
    stk = {"Authorization": f"Bearer {sess.get('session_token', '')}"}
    sid = sess.get("session_id", "")

    # -- 2. intersection: scope escalation denied (§5.1) -------------------
    r = hello([{**cap, "scopes": ["chat", "admin"]}])
    env = envelope_of(r)
    check("5.1 scope escalation denied", r.status_code == 403 and env is not None
          and env["code"] == "capability_denied", f"HTTP {r.status_code}: {r.text[:200]}")

    # -- 3. session_id / token binding (§7.2) ------------------------------
    r = c.post(f"{base}/avp/resolve_secrets", headers=stk, json={
        "avp_version": "1.0", "type": "resolve_secrets", "session_id": "ses_forged",
        "filters": {"format": "environment"}})
    check("7.2 mismatched session_id rejected", r.status_code == 403)

    # -- 4. secret bundle formats (§7.2) -----------------------------------
    r = c.post(f"{base}/avp/resolve_secrets", headers=stk, json={
        "avp_version": "1.0", "type": "resolve_secrets", "session_id": sid,
        "filters": {"format": "environment"}})
    body = r.json() if r.status_code == 200 else {}
    check("7.2 environment bundle", r.status_code == 200
          and body.get("type") == "secret_bundle"
          and body.get("secrets", {}).get("OPENAI_API_KEY") == "sk-conformance-fake",
          f"HTTP {r.status_code}: {r.text[:200]}")
    r = c.post(f"{base}/avp/resolve_secrets", headers=stk, json={
        "avp_version": "1.0", "type": "resolve_secrets", "session_id": sid,
        "filters": {"format": "json"}})
    body = r.json() if r.status_code == 200 else {}
    check("7.2 json bundle", r.status_code == 200
          and body.get("secrets", {}).get("openai", {}).get("api_key") == "sk-conformance-fake")

    # -- 5. strict field validation (§6) -----------------------------------
    r = c.post(f"{base}/avp/resolve_secrets", headers=stk, json={
        "avp_version": "1.0", "type": "resolve_secrets", "session_id": sid,
        "filters": {"format": "environment"}, "surprise_field": True})
    env = envelope_of(r)
    check("6   unknown fields rejected", r.status_code == 422 and env is not None
          and env["code"] == "validation_error", f"HTTP {r.status_code}: {r.text[:200]}")

    # -- 6. error envelope shape everywhere (§9) ---------------------------
    r = c.post(f"{base}/avp/agent_hello", headers={"Authorization": "Bearer agt_bogus"}, json={
        "avp_version": "1.0", "type": "agent_hello", "agent_id": agent_id,
        "agent_version": "0.0.0", "runtime": "x", "metadata": {}, "requested_capabilities": [cap]})
    check("9   auth failure is 401 with envelope", r.status_code == 401 and envelope_of(r) is not None,
          f"HTTP {r.status_code}: {r.text[:200]}")

    # -- 7. immediate revocation (§7.4/§7.5) -------------------------------
    r = c.post(f"{base}/avp/session_revoke", headers=stk, json={
        "avp_version": "1.0", "type": "session_revoke", "session_id": sid, "reason": "conformance"})
    check("7.4 session_revoke accepted", r.status_code == 200)
    r = c.post(f"{base}/avp/resolve_secrets", headers=stk, json={
        "avp_version": "1.0", "type": "resolve_secrets", "session_id": sid,
        "filters": {"format": "environment"}})
    check("7.5 revoked session rejected immediately", r.status_code == 401)

    # -- cleanup -----------------------------------------------------------
    c.delete(f"{base}/secrets", headers=ptk,
             params={"service_name": "openai", "label": label, "environment": "prod"})

    print(f"\n{len(PASSES)} passed, {len(FAILS)} failed"
          + (f" — NOT conformant: {FAILS}" if FAILS else " — AVP 1.0 conformant"))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
