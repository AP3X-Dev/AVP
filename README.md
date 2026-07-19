<div align="center">
  <img src=".github/images/avp_header.png" alt="Agent Vault Protocol" width="800"/>
</div>

# Agent Vault Protocol (AVP)

This repo contains the AVP 1.0 specification and its reference implementation.

- **Specification:** [docs/AVP_v1_SPEC.md](docs/AVP_v1_SPEC.md) — the wire
  protocol, capability model, session lifecycle, error registry, and security
  requirements. Where spec and code disagree, the spec wins.
- **Message schemas:** [docs/schemas/](docs/schemas/) — JSON Schema for every
  wire message (CI fails if they drift from the implementation).
- **Conformance suite:** `python server/scripts/conformance.py --url <vault>
  --principal-token <ptk>` — runnable against any vault claiming AVP 1.0
  conformance. CI runs it against this implementation on every push.

What is included

1. FastAPI server implementing control plane and AVP data plane
2. Postgres schema migration
3. AES GCM encrypted secret storage with versioning and soft deletion
4. Argon2 token hashing for principal, agent, and session tokens
5. Capability intersection, label binding, and session enforcement
6. Secret resolution bundles (environment and json)
7. Proxy calls for OpenAI Chat Completions and Anthropic Messages (proxy only mode)
8. Principal-scoped audit log with query endpoint
9. Web dashboard at /dashboard (sessions, audit trail, secrets, tokens — with revoke/rollback controls)
10. CLI to replace .env workflows (secrets, agents, sessions, audit)
11. Python and Node SDKs
12. Example agent script

## Quickstart (Docker)

1. Copy env file and edit as needed

```bash
cp .env.example .env
```

2. Start Postgres and the server

```bash
docker compose up --build
```

3. Bootstrap a principal (dev mode only)

```bash
python -m cli.avp_cli.main init --url http://localhost:8000 --email you@example.com --name "You"
```

4. Add an OpenAI secret

```bash
python -m cli.avp_cli.main add-secret --service openai --label personal_default --environment prod --api-key sk_your_key
```

5. Create an agent and agent token

```bash
python -m cli.avp_cli.main create-agent --agent-id deep_researcher --name "Deep Researcher"
python -m cli.avp_cli.main create-agent-token --agent-id deep_researcher
```

6. Run an example script without a .env file

```bash
python -m cli.avp_cli.main run --agent-id deep_researcher -- python examples/langgraph/main.py
```

## Notes

Security model

This MVP uses a local DEK derived from AVP_DEK_B64 for encrypting secrets. In production you should wrap the DEK using a real KMS. The code is structured so you can replace the local key provider.

Proxy calls

Proxy calls are implemented for OpenAI Chat Completions and Anthropic Messages using the stored API keys. The agent never receives the key in proxy only mode.

Useful CLI commands

```bash
python -m cli.avp_cli.main list-secrets
python -m cli.avp_cli.main delete-secret --service openai --label personal_default
python -m cli.avp_cli.main list-agents
python -m cli.avp_cli.main list-sessions
python -m cli.avp_cli.main revoke-session --session-id ses_abc123
python -m cli.avp_cli.main audit --event-type secret_resolved --limit 50
```

## Repo layout

- server/avp_server: FastAPI server
- server/migrations: SQL migration files
- cli/avp_cli: CLI tool
- sdk-python/avp_client: Python SDK
- sdk-node: Node/TypeScript SDK
- examples/langgraph: simple example script
