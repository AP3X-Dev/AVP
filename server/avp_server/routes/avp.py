from __future__ import annotations

from datetime import datetime, timedelta, timezone
import secrets
import json
from typing import Any, Dict, List, Optional, Tuple

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from psycopg.rows import dict_row

from ..deps import get_conn, require_agent, require_session
from ..db import fetchone, fetchall, execute
from ..models import AgentHello, AgentSession, ResolveSecrets, SecretBundle, ProxyCall, ProxyResult, ProxyError, SessionRevoke, SessionStatusResponse, AVPError, Capability
from ..auth import new_token, token_sha256, hash_token
from ..policy import intersect_capabilities
from ..crypto import decrypt_json
from ..services.registry import get_service_spec, format_env, operation_allowed
from ..services.openai_proxy import openai_chat_completion, openai_embeddings, openai_chat_target
from ..services.anthropic_proxy import anthropic_messages, anthropic_messages_target
from ..services.totp import totp_code
from ..audit import audit_event
from ..config import settings
from ..rate_limit import rate_limiter, allow_db
from ..session_utils import assert_valid_handle, _avp_error, _iso
from ..secret_selection import select_secret

router = APIRouter(prefix="/avp", tags=["avp"])

# (service, operation) -> async adapter(secret_data, payload) -> (status_code, data)
PROXY_ADAPTERS = {
    ("openai", "chat"): openai_chat_completion,
    ("openai", "embeddings"): openai_embeddings,
    ("anthropic", "messages"): anthropic_messages,
    ("totp", "code"): totp_code,
}

# Operations that support SSE streaming when payload has stream=true.
# Each value builds (url, headers) for the upstream request.
STREAM_TARGETS = {
    ("openai", "chat"): openai_chat_target,
    ("anthropic", "messages"): anthropic_messages_target,
}


def _select_secret(conn, principal_id: int, service: str, environment: str, resource: Optional[str]):
    """Wrapper for select_secret that provides fetchone function."""
    return select_secret(fetchone, conn, principal_id, service, environment, resource)


@router.post("/agent_hello", response_model=AgentSession)
def agent_hello(msg: AgentHello, request: Request, agent_token=Depends(require_agent), conn=Depends(get_conn)):
    principal_id = agent_token["principal_id"]
    agent_db_id = agent_token["agent_id"]
    if not agent_db_id:
        raise HTTPException(status_code=401, detail="invalid agent token linkage")

    # Validate agent identity
    agent_row = fetchone(conn, "SELECT id, agent_id, default_policy FROM agents WHERE id = %s AND principal_id = %s", [agent_db_id, principal_id])
    if not agent_row:
        raise HTTPException(status_code=401, detail="agent not found")
    if agent_row["agent_id"] != msg.agent_id:
        raise HTTPException(status_code=403, detail="agent_id mismatch")

    session_template = agent_token["session_template"] or {}
    allowed_caps = session_template.get("allowed_capabilities") or []
    max_session_seconds = int(session_template.get("max_session_seconds") or 3600)
    max_session_seconds = max(60, min(max_session_seconds, 12 * 3600))

    requested = [c.model_dump() for c in msg.requested_capabilities]
    granted = intersect_capabilities(requested, allowed_caps)

    if not granted:
        raise HTTPException(status_code=403, detail=_avp_error("capability_denied", "no requested capabilities were granted").model_dump())

    session_id = "ses_" + secrets.token_urlsafe(18)
    session_token = new_token("stk_")
    st_sha = token_sha256(session_token)
    st_hash = hash_token(session_token)

    expires_at = datetime.now(timezone.utc) + timedelta(seconds=max_session_seconds)

    execute(conn, """
        INSERT INTO sessions (
            session_id, principal_id, agent_id, agent_logical_id,
            session_token_sha256, session_token_hash,
            granted_capabilities, constraints, expires_at
        ) VALUES (
            %s, %s, %s, %s,
            %s, %s,
            %s::jsonb, %s::jsonb, %s
        )
    """, [
        session_id, principal_id, agent_db_id, msg.agent_id,
        st_sha, st_hash,
        json.dumps(granted), json.dumps({"max_session_seconds": max_session_seconds}), expires_at
    ])

    sess = fetchone(conn, "SELECT id FROM sessions WHERE session_id = %s", [session_id])
    session_db_id = sess["id"]

    capability_handles: Dict[str, str] = {}

    for cap in granted:
        service = cap["service"]
        scopes = cap.get("scopes") or []
        env = cap.get("environment")
        resource = cap.get("resource")
        mode = cap.get("mode") or "both"

        execute(conn, """
            INSERT INTO session_capabilities (session_id, service_name, scopes, environment, resource, mode)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, [session_db_id, service, scopes, env, resource, mode])

        if mode in ("proxy_only", "both"):
            handle = "hnd_" + secrets.token_urlsafe(18)
            execute(conn, """
                INSERT INTO capability_handles (handle, session_id, service_name, scopes, environment, resource, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, [handle, session_db_id, service, scopes, env, resource, expires_at])

            # key by service for v1, last one wins if duplicates
            capability_handles[service] = handle

    audit_event(
        conn,
        principal_id=principal_id,
        agent_db_id=agent_db_id,
        session_db_id=session_db_id,
        session_id=session_id,
        event_type="session_created",
        metadata={"granted_count": len(granted)},
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    conn.commit()

    return AgentSession(
        session_id=session_id,
        session_token=session_token,
        agent_id=msg.agent_id,
        principal_id=str(principal_id),
        granted_capabilities=[Capability(**c) for c in granted],
        expires_at=_iso(expires_at),
        constraints={"max_session_seconds": max_session_seconds},
        capability_handles=capability_handles
    )


@router.post("/resolve_secrets", response_model=SecretBundle)
def resolve_secrets(msg: ResolveSecrets, request: Request, session=Depends(require_session), conn=Depends(get_conn)):
    if session["session_id"] != msg.session_id:
        raise HTTPException(status_code=403, detail="session_id mismatch")

    session_db_id = session["id"]
    principal_id = session["principal_id"]
    agent_db_id = session["agent_id"]

    filters = msg.filters
    wanted_services = set(filters.services or [])

    caps = fetchall(conn, """
        SELECT service_name, scopes, environment, resource, mode
        FROM session_capabilities
        WHERE session_id = %s
    """, [session_db_id])

    env_out: Dict[str, Any] = {}
    json_out: Dict[str, Any] = {}

    for cap in caps:
        service = cap["service_name"]
        mode = cap["mode"]
        environment = cap["environment"]
        resource = cap["resource"]  # AVP-010: resource is the secret label

        if wanted_services and service not in wanted_services:
            continue
        if mode not in ("secret_resolution", "both"):
            continue

        spec = get_service_spec(service)
        if not spec:
            raise HTTPException(status_code=400, detail=_avp_error("unknown_service", f"unknown service {service}").model_dump())

        # Some credentials must never leave the vault whatever the grant says
        # (a TOTP seed mints codes forever). Skipping here — rather than trusting
        # the capability's mode — keeps that true even for a misconfigured grant,
        # and covers the `json` format, which returns the raw secret unmapped.
        if not spec.resolvable:
            continue

        # AVP-010/011: Select secret by label binding
        secret, error = _select_secret(conn, principal_id, service, environment, resource)
        if error:
            # Determine error code based on whether it's a label issue or missing secret
            code = "capability_denied" if "missing resource label" in error else "secret_not_found"
            raise HTTPException(status_code=400, detail=_avp_error(code, error).model_dump())

        ver = fetchone(conn, """
            SELECT data_ciphertext, key_version
            FROM secret_versions
            WHERE secret_id = %s AND is_current = TRUE
            ORDER BY version DESC
            LIMIT 1
        """, [secret["id"]])

        if not ver:
            raise HTTPException(status_code=500, detail=_avp_error("internal_error", "secret version missing").model_dump())

        try:
            secret_data = decrypt_json(bytes(ver["data_ciphertext"]), key_version=ver["key_version"])
        except Exception:
            raise HTTPException(status_code=500, detail=_avp_error("internal_error", "failed to decrypt secret").model_dump())

        if filters.format == "environment":
            env_piece = format_env(service, secret_data)
            env_out.update(env_piece)
        else:
            json_out[service] = secret_data

        audit_event(
            conn,
            principal_id=principal_id,
            agent_db_id=agent_db_id,
            session_db_id=session_db_id,
            session_id=msg.session_id,
            event_type="secret_resolved",
            service_name=service,
            metadata={"format": filters.format},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

    conn.commit()

    secrets_payload = env_out if filters.format == "environment" else json_out
    env_name = "prod"
    if caps:
        env_name = str(caps[0]["environment"]) if str(caps[0]["environment"]) in ("dev","staging","prod") else "prod"
    return SecretBundle(session_id=msg.session_id, environment=env_name, secrets=secrets_payload)


@router.post("/proxy_call", response_model=ProxyResult)
async def proxy_call(msg: ProxyCall, request: Request, session=Depends(require_session), conn=Depends(get_conn)):
    if session["session_id"] != msg.session_id:
        raise HTTPException(status_code=403, detail="session_id mismatch")

    session_db_id = session["id"]
    principal_id = session["principal_id"]
    agent_db_id = session["agent_id"]

    handle = fetchone(conn, """
        SELECT id, handle, service_name, scopes, environment, resource, expires_at
        FROM capability_handles
        WHERE handle = %s AND session_id = %s
    """, [msg.capability_handle, session_db_id])

    if not handle:
        raise HTTPException(status_code=404, detail=_avp_error("operation_not_allowed", "invalid capability handle").model_dump())

    # Enforce handle expiration (AVP-003)
    assert_valid_handle(handle)

    service = handle["service_name"]
    scopes = list(handle["scopes"] or [])
    environment = handle["environment"]
    resource = handle["resource"]  # AVP-010: resource is the secret label

    if not operation_allowed(service, msg.operation, scopes):
        raise HTTPException(status_code=403, detail=_avp_error("operation_not_allowed", "operation not allowed by scopes").model_dump())

    limit = settings.proxy_rate_limit_per_minute
    if settings.rate_limit_backend == "postgres":
        ok = allow_db(fetchone, execute, conn, f"{msg.session_id}:{service}:{msg.operation}", limit)
        conn.commit()  # persist the counter even when this request is rejected
    else:
        ok = rate_limiter.allow(msg.session_id, service, msg.operation, capacity=float(limit), refill_per_sec=limit / 60.0)
    if not ok:
        raise HTTPException(status_code=429, detail=_avp_error("rate_limit_exceeded", "rate limit exceeded").model_dump())

    # AVP-010/011: Select secret by label binding
    secret, error = _select_secret(conn, principal_id, service, environment, resource)
    if error:
        code = "capability_denied" if "missing resource label" in error else "secret_not_found"
        raise HTTPException(status_code=400, detail=_avp_error(code, error).model_dump())

    ver = fetchone(conn, """
        SELECT data_ciphertext, key_version
        FROM secret_versions
        WHERE secret_id = %s AND is_current = TRUE
        ORDER BY version DESC
        LIMIT 1
    """, [secret["id"]])
    if not ver:
        raise HTTPException(status_code=500, detail=_avp_error("internal_error", "secret version missing").model_dump())

    secret_data = decrypt_json(bytes(ver["data_ciphertext"]), key_version=ver["key_version"])

    request_id = "req_" + secrets.token_urlsafe(16)

    if msg.payload.get("stream"):
        return await _proxy_call_streaming(
            conn, request, msg, session, service, secret_data, request_id,
            principal_id=principal_id, agent_db_id=agent_db_id, session_db_id=session_db_id,
        )

    adapter = PROXY_ADAPTERS.get((service, msg.operation))
    try:
        if adapter:
            status_code, data = await adapter(secret_data, msg.payload)
            if 200 <= status_code < 300:
                result = ProxyResult(request_id=request_id, status="ok", result=data)
            else:
                result = ProxyResult(request_id=request_id, status="error", error=ProxyError(code="proxy_failure", message=str(data.get("error", {}).get("message", "proxy error"))), result=data)
        else:
            result = ProxyResult(request_id=request_id, status="error", error=ProxyError(code="unknown_service", message="no proxy adapter for this operation"))
    except Exception as e:
        result = ProxyResult(request_id=request_id, status="error", error=ProxyError(code="proxy_failure", message=str(e)))

    audit_event(
        conn,
        principal_id=principal_id,
        agent_db_id=agent_db_id,
        session_db_id=session_db_id,
        session_id=msg.session_id,
        event_type="proxy_call",
        service_name=service,
        request_id=request_id,
        metadata={"operation": msg.operation, "status": result.status},
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    conn.commit()
    return result


async def _proxy_call_streaming(conn, request: Request, msg: ProxyCall, session, service: str,
                                secret_data: Dict[str, Any], request_id: str, *,
                                principal_id, agent_db_id, session_db_id):
    """Stream an upstream SSE response back to the agent verbatim.

    The audit event is written and committed before streaming starts, since the
    request connection is released once the response begins.
    """
    target_builder = STREAM_TARGETS.get((service, msg.operation))
    if target_builder is None:
        return JSONResponse(status_code=200, content=ProxyResult(
            request_id=request_id, status="error",
            error=ProxyError(code="stream_not_supported", message="streaming not supported for this operation"),
        ).model_dump())

    target = target_builder(secret_data)
    if target is None:
        return JSONResponse(status_code=200, content=ProxyResult(
            request_id=request_id, status="error",
            error=ProxyError(code="internal_error", message="missing api_key in secret"),
        ).model_dump())
    url, headers = target

    audit_event(
        conn,
        principal_id=principal_id,
        agent_db_id=agent_db_id,
        session_db_id=session_db_id,
        session_id=msg.session_id,
        event_type="proxy_call",
        service_name=service,
        request_id=request_id,
        metadata={"operation": msg.operation, "status": "stream", "stream": True},
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    conn.commit()

    # ponytail: generous fixed timeout; make configurable if long generations exceed it
    client = httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=10.0))
    try:
        upstream_req = client.build_request("POST", url, headers=headers, json=msg.payload)
        upstream = await client.send(upstream_req, stream=True)
    except Exception as e:
        await client.aclose()
        return JSONResponse(status_code=200, content=ProxyResult(
            request_id=request_id, status="error",
            error=ProxyError(code="proxy_failure", message=str(e)),
        ).model_dump())

    if upstream.status_code >= 300:
        body = await upstream.aread()
        await upstream.aclose()
        await client.aclose()
        try:
            data = json.loads(body)
        except Exception:
            data = {"raw": body.decode(errors="replace")}
        message = str(data.get("error", {}).get("message", "proxy error")) if isinstance(data, dict) else "proxy error"
        return JSONResponse(status_code=200, content=ProxyResult(
            request_id=request_id, status="error",
            error=ProxyError(code="proxy_failure", message=message),
            result=data if isinstance(data, dict) else {"raw": str(data)},
        ).model_dump())

    async def _relay():
        try:
            async for chunk in upstream.aiter_bytes():
                yield chunk
        finally:
            await upstream.aclose()
            await client.aclose()

    media_type = upstream.headers.get("content-type", "text/event-stream")
    return StreamingResponse(_relay(), media_type=media_type, headers={"x-avp-request-id": request_id})


@router.post("/session_revoke")
def session_revoke(msg: SessionRevoke, request: Request, session=Depends(require_session), conn=Depends(get_conn)):
    if session["session_id"] != msg.session_id:
        raise HTTPException(status_code=403, detail="session_id mismatch")

    execute(conn, "UPDATE sessions SET revoked_at = now(), revoked_reason = %s WHERE id = %s", [msg.reason, session["id"]])
    audit_event(
        conn,
        principal_id=session["principal_id"],
        agent_db_id=session["agent_id"],
        session_db_id=session["id"],
        session_id=msg.session_id,
        event_type="session_revoked",
        metadata={"reason": msg.reason},
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    conn.commit()
    return {"ok": True}


@router.get("/session_status", response_model=SessionStatusResponse)
def session_status(session_id: str, session=Depends(require_session), conn=Depends(get_conn)):
    if session["session_id"] != session_id:
        raise HTTPException(status_code=403, detail="session_id mismatch")
    # Convert granted capabilities stored in DB json
    caps = session["granted_capabilities"]
    highlights = [Capability(**c) for c in caps]
    return SessionStatusResponse(
        session_id=session_id,
        active=True,
        expires_at=session["expires_at"].isoformat(),
        granted_capabilities=highlights
    )
