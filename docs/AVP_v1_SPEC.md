# Agent Vault Protocol — Version 1.0

**Status:** Draft specification. The implementation in this repository is the
reference implementation; where they disagree, this document wins and the
implementation has a bug.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be
interpreted as described in RFC 2119.

---

## 1. Purpose and scope

AVP defines how an autonomous **agent** obtains scoped, short-lived,
revocable access to third-party service credentials held by a **vault** on
behalf of a **principal** — without the agent ever holding long-lived
credentials, and optionally without the agent ever seeing a credential at all.

This document specifies the wire protocol: message formats, the capability
model, session lifecycle, error handling, and versioning. It does not mandate
a storage design, encryption scheme, or deployment topology; those are vault
implementation concerns (see §10 for the security properties a vault MUST
nonetheless uphold).

## 2. Actors and trust model

- **Principal** — the human or organization that owns credentials and defines
  policy. Trusts the vault fully. Does not trust agents beyond the policy it
  grants them.
- **Agent** — a client process acting for a principal. Untrusted by default;
  everything it can do is bounded by capability grants.
- **Vault** — the server implementing this protocol. Holds credentials,
  enforces policy, issues sessions, records audit events.

## 3. Transport

- Messages are JSON objects exchanged over HTTP. Production deployments MUST
  use TLS.
- Authentication is via `Authorization: Bearer <token>` headers.
- Data-plane endpoints (§7) are rooted at `/avp/`. Control-plane paths (§8)
  are RECOMMENDED shapes, not wire-normative.

## 4. Tokens

Three bearer token classes exist. A vault MUST NOT accept a token of one
class where another is required.

| Class | Prefix (RECOMMENDED) | Held by | Lifetime |
|---|---|---|---|
| Principal token | `ptk_` | principal | long-lived, revocable |
| Agent token | `agt_` | agent process | long-lived or expiring, revocable |
| Session token | `stk_` | agent, per session | short-lived (bounded, see §7.1), revocable |

Vaults MUST store tokens only in hashed form and MUST be able to revoke any
token with immediate effect (revocation checked on every request).

## 5. The capability model

A **capability** is the unit of grant:

```json
{
  "service":     "openai",          // service identifier from the vault's registry
  "scopes":      ["chat"],          // operation classes, subset semantics
  "environment": "prod",            // one of: dev, staging, prod
  "resource":    "default",         // credential label binding, nullable
  "mode":        "both"             // secret_resolution | proxy_only | both
}
```

- `resource` binds the capability to the credential with the matching label
  for that service and environment (**label binding**). When `resource` is
  null, the vault MUST reject resolution unless it is explicitly configured
  to fall back to a default credential.
- `mode` limits how the capability may be exercised: receiving credential
  material (`secret_resolution`), making vault-mediated calls without ever
  receiving material (`proxy_only`), or either (`both`).

### 5.1 Intersection algorithm (normative)

A session's granted capabilities are the intersection of what the agent
requested with what the agent's token template allows. For each requested
capability R, evaluated against each allowed capability A with the same
`(service, environment)` pair, the first A that satisfies all of the
following yields a grant:

1. `R.scopes ⊆ A.scopes`
2. mode: if `A.mode = "both"`, granted mode is `R.mode`; otherwise granted
   mode is `A.mode`, and R MUST have requested `A.mode` or `"both"`.
3. resource: if `A.resource` is non-null, `R.resource` MUST equal it exactly;
   if `A.resource` is null, `R.resource` MUST be null.

Requested capabilities with no satisfying A are silently dropped. If nothing
is granted, the vault MUST reject session creation with `capability_denied`.
A vault MUST NOT grant anything broader than the template allows.

## 6. Message envelope

Every data-plane message is a JSON object carrying:

- `avp_version` — protocol version string, `"1.0"` for this document
- `type` — message type name (snake_case)

Message types defined by this version, with JSON Schemas in
[`docs/schemas/`](schemas/):

| `type` | Direction | Schema |
|---|---|---|
| `agent_hello` | agent → vault | `agent_hello.schema.json` |
| `agent_session` | vault → agent | `agent_session.schema.json` |
| `resolve_secrets` | agent → vault | `resolve_secrets.schema.json` |
| `secret_bundle` | vault → agent | `secret_bundle.schema.json` |
| `proxy_call` | agent → vault | `proxy_call.schema.json` |
| `proxy_result` | vault → agent | `proxy_result.schema.json` |
| `session_revoke` | agent → vault | `session_revoke.schema.json` |
| `session_status_response` | vault → agent | `session_status_response.schema.json` |
| `error` | vault → agent | `error.schema.json` |

Vaults MUST reject messages containing fields not defined by the declared
`avp_version` (see §11 for how this interacts with evolution).

## 7. Data plane

### 7.1 Session establishment — `POST /avp/agent_hello`

The agent authenticates with its agent token and sends `agent_hello` naming
its `agent_id` and requested capabilities. The vault MUST:

1. Verify the token maps to the named agent (reject mismatches).
2. Run the intersection algorithm (§5.1).
3. Issue a session: an unguessable `session_id`, a session token, an
   expiry (bounded by the template; vaults SHOULD cap sessions at 12 hours
   and MUST enforce a minimum of 60 seconds), and — for each granted
   capability whose mode permits proxying — an opaque **capability handle**.
4. Record an audit event.

The response is an `agent_session` message. `capability_handles` maps
service name → handle.

### 7.2 Secret resolution — `POST /avp/resolve_secrets`

Authenticated by session token. The vault MUST verify the `session_id` in
the message matches the session of the presented token. For each granted
capability with a resolution-permitting mode (optionally filtered by the
request), the vault selects the credential per label binding and returns a
`secret_bundle` in the requested format:

- `environment` — a flat map of environment-variable names to values
- `json` — a map of service name to credential object

Each resolution MUST be audited per service.

**Non-resolvable services.** A service MAY declare that its credential
material must never be released. For such a service the vault MUST omit it
from the bundle in every format, regardless of the capability's `mode` — the
declaration is a property of the service, so it holds even where a grant was
misconfigured to permit resolution. Such a credential is reachable only
through `proxy_call` (§7.3). Omission follows the same convention as an
ungranted capability (§5.1): the service is dropped from the bundle rather
than failing the request, so a mixed resolution still returns what it may.

A vault SHOULD expose which services are resolvable through its service
discovery surface, so a client can tell before requesting a capability.

### 7.3 Vault-mediated calls — `POST /avp/proxy_call`

Authenticated by session token. The message names a `capability_handle`, an
`operation`, and a provider `payload`. The vault MUST:

1. Validate the handle belongs to this session and has not expired.
2. Validate the operation is permitted by the handle's scopes.
3. Enforce rate limits (limit-exceeded → `rate_limit_exceeded`).
4. Attach the credential server-side and forward the call. The agent MUST
   NOT receive the credential through this path.
5. Audit the call with a `request_id` echoed in the response.

The response is a `proxy_result`: `status` is `ok` or `error`; provider
failures are carried in `error` (and `result` MAY carry the provider's error
body). Vault-side failures during proxying MUST NOT leak credential material.

**Streaming:** if the payload requests streaming (`"stream": true`) and the
vault supports it for the operation, the vault relays the provider's SSE
stream verbatim with the provider's content type and SHOULD expose the
request id in an `x-avp-request-id` response header. If streaming is
unsupported for the operation the vault MUST respond with a `proxy_result`
error with code `stream_not_supported`. Upstream errors MUST be returned as a
`proxy_result` error rather than a broken stream.

#### 7.3.1 Derived credentials

Proxying is not limited to forwarding a call upstream. Where a stored secret's
purpose is to *derive* a short-lived value, the vault SHOULD perform the
derivation itself and return only the derived value, so the long-lived secret
never crosses the wire.

The `totp` service is the reference case. Its credential holds a base32 seed
(`seed`, REQUIRED) plus optional `digits`, `period` and `algorithm`. The
`code` operation returns an RFC 6238 one-time code:

```json
{ "code": "492039", "expires_in": 17, "period": 30, "digits": 6 }
```

`expires_in` is the whole seconds the code remains valid, so a caller can
choose to wait for the next window rather than race the boundary.

Two requirements make this meaningful rather than decorative:

- The seed MUST be declared non-resolvable (§7.2). A seed mints codes
  indefinitely, from anywhere, long after the session that obtained it was
  revoked — releasing it would convert a 30-second credential back into an
  unbounded one.
- The vault MUST derive the value from its own clock and MUST ignore any
  caller-supplied time in the payload, for the same reason: honouring one
  would let an agent mint codes for arbitrary points in time.

### 7.4 Session revocation and status

- `POST /avp/session_revoke` — revokes the presented session. After
  revocation the session token MUST be rejected everywhere, immediately.
- `GET /avp/session_status?session_id=…` — returns
  `session_status_response` for the presented session.

### 7.5 Session lifecycle

```
            agent_hello                     expiry reached
  (none) ────────────────► ACTIVE ──────────────────────────► EXPIRED
                             │
                             │ session_revoke, or principal-side revocation
                             ▼
                          REVOKED
```

EXPIRED and REVOKED are terminal. A vault MUST reject session tokens for
non-ACTIVE sessions with `session_expired` / `session_revoked` semantics
(401 at authentication, or the corresponding error code where the session is
referenced).

## 8. Control plane (RECOMMENDED shapes)

The control plane is principal-facing vault management. Its shapes are
RECOMMENDED for interoperability of tooling but are not wire-normative:
agents never depend on them. A conforming vault MUST provide equivalent
functionality: agent registration, agent token issuance, credential
write/list/delete, credential version history and rollback, session listing
and revocation, token listing and revocation, and audit log retrieval scoped
to the principal. Credential *values* MUST NOT be retrievable through any
control-plane read.

## 9. Errors

Errors use the `error` message envelope:

```json
{ "avp_version": "1.0", "type": "error",
  "code": "capability_denied", "message": "…", "details": { } }
```

`details` MAY include a `correlation_id` for support. Vaults MUST NOT leak
internal details (stack traces, SQL, key material) in production errors.

### 9.1 Error code registry (v1.0)

| Code | Meaning |
|---|---|
| `validation_error` | request failed schema validation |
| `invalid_request` | malformed request |
| `capability_denied` | capability not granted / label binding unsatisfied |
| `capability_expired` | capability handle expired |
| `session_expired` | session past expiry |
| `session_revoked` | session was revoked |
| `secret_not_found` | no credential matches the binding |
| `operation_not_allowed` | operation not permitted by scopes |
| `rate_limit_exceeded` | too many requests |
| `unknown_service` | service not in the vault's registry |
| `stream_not_supported` | streaming requested for a non-streaming operation |
| `proxy_failure` | upstream provider call failed |
| `http_error` | generic HTTP-layer error |
| `internal_error` | unexpected vault error |

New codes may be added in minor versions; clients MUST treat unknown codes as
non-retryable failures of their category (4xx vs 5xx).

## 10. Security considerations

- **Credential confinement.** In `proxy_only` mode the credential MUST NOT
  appear in any response body, header, or stream visible to the agent.
- **Confinement independent of grants.** Where a credential must never be
  released at all, that MUST be enforced as a property of the service (§7.2)
  rather than left to the capability's `mode`, which is per-grant operator
  configuration and can therefore be set wrongly. Prefer deriving a
  short-lived value in the vault (§7.3.1) over releasing the long-lived
  secret that produces it.
- **Token storage.** Vaults MUST store all tokens hashed with a
  memory-hard or otherwise collision- and preimage-resistant scheme, and use
  constant-time comparison for any fixed shared secrets.
- **Encryption at rest.** Credential material MUST be encrypted at rest.
  Vaults SHOULD support key rotation such that rotating the active key does
  not orphan previously encrypted material.
- **Audit.** Session creation, credential resolution, proxied calls, and all
  revocations MUST be audited. Audit records MUST NOT contain credential
  material.
- **Least privilege by construction.** The intersection algorithm is the
  only path to a grant; there MUST be no side channel that widens a session
  beyond its agent token template.

## 11. Versioning

- `avp_version` is `MAJOR.MINOR`. This document defines `1.0`.
- Vaults MUST reject messages whose `avp_version` they do not support with
  `validation_error` (422).
- MINOR revisions are additive: new message types, new optional response
  fields, new error codes. Because vaults reject unknown *request* fields,
  clients MUST NOT send fields beyond the version they declare.
- MAJOR revisions may break compatibility and use a distinct version string.

## 12. Conformance

An implementation may claim AVP 1.0 conformance if it passes the conformance
suite in [`server/scripts/conformance.py`](../server/scripts/conformance.py),
which exercises, against a live vault:

1. Session establishment and envelope shape (§6, §7.1)
2. Intersection enforcement — scope escalation denied (§5.1)
3. Session/token binding — mismatched `session_id` rejected (§7.2)
4. Secret bundle formats (§7.2)
5. Strict field validation — unknown fields rejected (§6)
6. Error envelope shape and codes (§9)
7. Immediate revocation (§7.4, §7.5)

Run: `python server/scripts/conformance.py --url <vault> --principal-token <ptk>`
(the suite creates and cleans up its own agent, credential, and sessions).

---

*The JSON Schemas in `docs/schemas/` are generated from the reference
implementation's message models and are normative for message shapes; the
reference repository's test suite fails if they drift.*
