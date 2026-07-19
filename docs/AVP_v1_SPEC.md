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
- POST /secrets, GET /secrets, DELETE /secrets (soft delete)
- GET /sessions, POST /sessions/{session_id}/revoke
- GET /audit — principal-scoped audit log (filter by event_type, session_id)
- GET /services — service registry discovery
- POST /dev/bootstrap_principal (dev mode), POST /admin/bootstrap_principal (one-time token)

Proxy adapters

- openai: `chat` (Chat Completions)
- anthropic: `messages` (Messages API)

The agent never receives the underlying API key in proxy_only mode.

MVP constraints

- Secrets are encrypted using AES GCM with a local DEK from AVP_DEK_B64
  (wrap the DEK with a real KMS in production; the key provider is pluggable)
- Rate limiting is in-memory per server process
