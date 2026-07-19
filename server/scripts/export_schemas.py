"""Export JSON Schemas for every AVP wire message into docs/schemas/.

Run from the repo root: python server/scripts/export_schemas.py
The test suite fails if the exported schemas drift from the models.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from avp_server.models import (  # noqa: E402
    AgentHello, AgentSession, ResolveSecrets, SecretBundle,
    ProxyCall, ProxyResult, SessionRevoke, SessionStatusResponse, AVPError,
)

MESSAGE_MODELS = {
    "agent_hello": AgentHello,
    "agent_session": AgentSession,
    "resolve_secrets": ResolveSecrets,
    "secret_bundle": SecretBundle,
    "proxy_call": ProxyCall,
    "proxy_result": ProxyResult,
    "session_revoke": SessionRevoke,
    "session_status_response": SessionStatusResponse,
    "error": AVPError,
}


def schema_for(model) -> dict:
    schema = model.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    return schema


def main() -> None:
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "docs", "schemas"))
    os.makedirs(out_dir, exist_ok=True)
    for name, model in MESSAGE_MODELS.items():
        path = os.path.join(out_dir, f"{name}.schema.json")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(schema_for(model), f, indent=2, sort_keys=True)
            f.write("\n")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
