# AVP v1.0 (MVP reference)

This document describes what the code in this repo implements.

Actors

- Principal: owner of a vault, controls secrets and agent policies
- Agent: a client process that requests capabilities and then resolves secrets or uses proxy calls
- Vault: the AVP server, stores encrypted secrets and issues scoped sessions

Tokens

- Principal token: bearer token used for control plane endpoints
- Agent token: bearer token tied to a single agent under a principal
- Session token: short lived bearer token issued during agent_hello

Capability

A capability is a tuple:

- service
- scopes (subset)
- environment
- optional resource (maps to the secret's label — see Label binding)
- mode: secret_resolution, proxy_only, or both

Flow

1. Principal creates agent and agent token
2. Agent calls /avp/agent_hello with requested capabilities
3. Vault intersects requested capabilities with the agent token session template
4. Vault issues a session and returns a session token plus capability handles for proxy calls
5. Agent calls /avp/resolve_secrets to receive a secret bundle (if allowed)
6. Agent calls /avp/proxy_call to perform a remote operation (if allowed)

Label binding

The `resource` field of a capability selects the secret whose `label` matches it
exactly (per service and environment). If `resource` is absent, the request is
rejected unless `AVP_ALLOW_LABEL_FALLBACK=true`, in which case the newest secret
for the service and environment is used.

Control plane endpoints

- POST /agents, GET /agents, POST /agents/{agent_id}/tokens
- GET /tokens, POST /tokens/{token_id}/revoke — token inventory and revocation
- POST /secrets, GET /secrets, DELETE /secrets (soft delete)
- GET /secrets/versions — version history (metadata only)
- POST /secrets/rollback — roll back to an earlier version (appends a new
  version carrying the old ciphertext; history stays intact)
- GET /sessions, POST /sessions/{session_id}/revoke
- GET /audit — principal-scoped audit log (filter by event_type, session_id)
- GET /services — service registry discovery
- GET /dashboard — self-contained web console (principal token entered in the
  browser; talks to the same-origin control API, no CORS, no server session)
- POST /dev/bootstrap_principal (dev mode), POST /admin/bootstrap_principal (one-time token)

Proxy adapters

- openai: `chat` (Chat Completions), `embeddings` (Embeddings)
- anthropic: `messages` (Messages API)

The agent never receives the underlying API key in proxy_only mode.

Streaming

Setting `"stream": true` in the proxy_call payload for `openai chat` or
`anthropic messages` relays the provider's SSE stream back verbatim
(Content-Type passthrough, `x-avp-request-id` header). Upstream errors return
a normal proxy_result envelope instead of a stream. Both SDKs expose this as
`proxy_call_stream` / `proxyCallStream`.

Key rotation

Every secret version records the key_version it was encrypted under. Configure
`AVP_DEK_KEYRING_B64` as a JSON map of key_version -> base64 DEK and set
`AVP_KEY_VERSION` to the version new writes should use; older versions remain
decryptable. To rotate: add the new key to the keyring, bump AVP_KEY_VERSION,
restart. Re-encrypt old versions at your leisure by re-saving secrets.

AWS KMS key provider

Set `AVP_KEY_PROVIDER=aws_kms` to keep only KMS-wrapped DEKs in the
environment; the server unwraps them via KMS Decrypt at startup (requires
`pip install 'avp-server[aws]'` and AWS credentials). Generate a wrapped DEK
with `python server/scripts/wrap_dek.py --kms-key-id alias/avp`. Rotation uses
`AVP_KMS_WRAPPED_KEYRING_B64`, a JSON map of key_version -> wrapped DEK.

Rate limiting

Proxy calls are limited per (session, service, operation). The default
backend is Postgres (fixed 1-minute window counters — survives restarts and
works across replicas); set `AVP_RATE_LIMIT_BACKEND=memory` for the
per-process token bucket. `AVP_PROXY_RATE_LIMIT_PER_MINUTE` sets the limit
(default 60).
