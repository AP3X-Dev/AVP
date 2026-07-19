from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

import typer
from rich import print

from .config_store import load_config, save_config, set_agent_token, get_agent_token
from .client import AVPHttpClient

app = typer.Typer(add_completion=False, help="AVP CLI (MVP)")


def _require_url(cfg: Dict[str, Any]) -> str:
    url = cfg.get("url")
    if not url:
        raise typer.BadParameter("Missing vault URL. Run: avp init --url http://localhost:8000")
    return url


def _require_principal_token(cfg: Dict[str, Any]) -> str:
    tok = cfg.get("principal_token")
    if not tok:
        raise typer.BadParameter("Missing principal token. Run: avp init or avp login")
    return tok


@app.command()
def init(url: str = typer.Option(..., help="AVP server URL"), email: str = typer.Option(...), name: str = typer.Option("User")):
    cfg = load_config()
    cfg["url"] = url
    client = AVPHttpClient(url)
    data = client.post("/dev/bootstrap_principal", json={"email": email, "display_name": name})
    cfg["principal_token"] = data["principal_token"]
    save_config(cfg)
    print("[green]Initialized AVP config[/green]")
    print(f"Principal id: {data['principal_id']}")


@app.command()
def login(token: str = typer.Option(..., help="Principal token"), url: Optional[str] = typer.Option(None, help="AVP server URL override")):
    cfg = load_config()
    if url:
        cfg["url"] = url
    cfg["principal_token"] = token
    save_config(cfg)
    print("[green]Saved principal token[/green]")


@app.command("create-agent")
def create_agent(
    agent_id: str = typer.Option(...),
    name: str = typer.Option(...),
    allow_openai: bool = typer.Option(True, help="Add a default policy allowing OpenAI chat in prod"),
    resource: Optional[str] = typer.Option("default", help="Secret label (resource) for OpenAI capability. Use the same label you used with add-secret."),
):
    cfg = load_config()
    url = _require_url(cfg)
    token = _require_principal_token(cfg)
    client = AVPHttpClient(url)

    default_policy: Dict[str, Any] = {}
    if allow_openai:
        # AVP-012: Include resource label in capability to enable label binding
        default_policy = {
            "allowed_capabilities": [
                {"service": "openai", "scopes": ["chat"], "environment": "prod", "resource": resource, "mode": "both"}
            ],
            "max_session_seconds": 3600
        }
        if resource:
            print(f"[yellow]Note:[/yellow] This agent can only use secrets with label '{resource}'. Create a matching secret with: avp add-secret --label {resource}")

    data = client.post("/agents", token=token, json={"agent_id": agent_id, "name": name, "description": None, "default_policy": default_policy})
    print("[green]Created agent[/green]", data)


@app.command("create-agent-token")
def create_agent_token(agent_id: str = typer.Option(...), store: bool = typer.Option(True, help="Store token in local config")):
    cfg = load_config()
    url = _require_url(cfg)
    token = _require_principal_token(cfg)
    client = AVPHttpClient(url)
    data = client.post(f"/agents/{agent_id}/tokens", token=token, json={})
    if store:
        set_agent_token(cfg, agent_id, data["token"])
        save_config(cfg)
        print("[green]Stored agent token in config[/green]")
    print("[green]Created agent token[/green]")
    print(data["token"])


@app.command("add-secret")
def add_secret(
    service: str = typer.Option(..., help="Service name, for MVP only openai"),
    label: str = typer.Option("default"),
    environment: str = typer.Option("prod"),
    api_key: str = typer.Option(..., help="API key value"),
    base_url: Optional[str] = typer.Option(None),
    org_id: Optional[str] = typer.Option(None),
):
    cfg = load_config()
    url = _require_url(cfg)
    token = _require_principal_token(cfg)
    client = AVPHttpClient(url)

    data: Dict[str, Any] = {"api_key": api_key}
    if base_url:
        data["base_url"] = base_url
    if org_id:
        data["org_id"] = org_id

    resp = client.post("/secrets", token=token, json={
        "service_name": service,
        "label": label,
        "environment": environment,
        "data": data,
        "meta": {}
    })
    print("[green]Saved secret[/green]", resp)


@app.command("list-secrets")
def list_secrets():
    cfg = load_config()
    url = _require_url(cfg)
    token = _require_principal_token(cfg)
    client = AVPHttpClient(url)
    resp = client.get("/secrets", token=token)
    print(resp)


@app.command("delete-secret")
def delete_secret(
    service: str = typer.Option(...),
    label: str = typer.Option("default"),
    environment: str = typer.Option("prod"),
):
    """Soft-delete a secret so it can no longer be resolved by agents."""
    cfg = load_config()
    url = _require_url(cfg)
    token = _require_principal_token(cfg)
    client = AVPHttpClient(url)
    client.delete("/secrets", token=token, params={"service_name": service, "label": label, "environment": environment})
    print(f"[green]Deleted secret[/green] {service}/{label} ({environment})")


@app.command("list-agents")
def list_agents():
    cfg = load_config()
    url = _require_url(cfg)
    token = _require_principal_token(cfg)
    client = AVPHttpClient(url)
    print(client.get("/agents", token=token))


@app.command("list-sessions")
def list_sessions():
    cfg = load_config()
    url = _require_url(cfg)
    token = _require_principal_token(cfg)
    client = AVPHttpClient(url)
    print(client.get("/sessions", token=token))


@app.command("revoke-session")
def revoke_session(session_id: str = typer.Option(...), reason: str = typer.Option("revoked")):
    cfg = load_config()
    url = _require_url(cfg)
    token = _require_principal_token(cfg)
    client = AVPHttpClient(url)
    client.post(f"/sessions/{session_id}/revoke", token=token, json={"reason": reason})
    print(f"[green]Revoked session[/green] {session_id}")


@app.command("list-tokens")
def list_tokens():
    """List API tokens (metadata only — token values are never retrievable)."""
    cfg = load_config()
    url = _require_url(cfg)
    token = _require_principal_token(cfg)
    client = AVPHttpClient(url)
    for t in client.get("/tokens", token=token):
        state = "revoked" if t.get("revoked_at") else "active"
        agent = f" agent={t['agent_id']}" if t.get("agent_id") else ""
        print(f"#{t['token_id']}  {t['token_type']}{agent}  {state}  created {t['created_at']}")


@app.command("revoke-token")
def revoke_token(token_id: int = typer.Option(...), reason: str = typer.Option("revoked")):
    """Revoke an API token by id (see list-tokens). Takes effect immediately."""
    cfg = load_config()
    url = _require_url(cfg)
    token = _require_principal_token(cfg)
    client = AVPHttpClient(url)
    client.post(f"/tokens/{token_id}/revoke", token=token, json={"reason": reason})
    print(f"[green]Revoked token[/green] #{token_id}")


@app.command("audit")
def audit(
    event_type: Optional[str] = typer.Option(None, help="Filter by event type, e.g. secret_resolved"),
    session_id: Optional[str] = typer.Option(None, help="Filter by session id"),
    limit: int = typer.Option(50, help="Max entries (up to 500)"),
):
    """Show recent audit log entries for your principal."""
    cfg = load_config()
    url = _require_url(cfg)
    token = _require_principal_token(cfg)
    client = AVPHttpClient(url)
    params: Dict[str, Any] = {"limit": limit}
    if event_type:
        params["event_type"] = event_type
    if session_id:
        params["session_id"] = session_id
    entries = client.get("/audit", token=token, params=params)
    for e in entries:
        svc = f" {e['service_name']}" if e.get("service_name") else ""
        sess = f" [{e['session_id']}]" if e.get("session_id") else ""
        print(f"{e['created_at']}  {e['event_type']}{svc}{sess}")


def _load_capabilities(capabilities_file: Optional[str], resource: Optional[str] = "default") -> List[Dict[str, Any]]:
    """Load capabilities from file or return default.

    AVP-012: resource label defaults to 'default' for label binding.
    """
    if not capabilities_file:
        # Default request: OpenAI chat, secret_resolution mode, prod
        # Resource defaults to 'default' to match typical secret setup
        return [{"service": "openai", "scopes": ["chat"], "environment": "prod", "resource": resource, "mode": "secret_resolution"}]
    p = Path(capabilities_file)
    raw = p.read_text(encoding="utf-8")
    val = json.loads(raw)
    if not isinstance(val, list):
        raise typer.BadParameter("capabilities file must be a JSON list")
    return val


@app.command("proxy-chat")
def proxy_chat(
    agent_id: str = typer.Option(...),
    prompt: str = typer.Option(..., help="User message"),
    model: str = typer.Option("gpt-4o-mini"),
    resource: Optional[str] = typer.Option("default", help="Secret label (resource) to use. Must match a secret created with add-secret."),
):
    cfg = load_config()
    url = _require_url(cfg)
    agent_token = os.environ.get("AVP_AGENT_TOKEN") or get_agent_token(cfg, agent_id)
    if not agent_token:
        raise typer.BadParameter("Missing agent token. Run: avp create-agent-token or set AVP_AGENT_TOKEN")

    client = AVPHttpClient(url)
    # AVP-012: Include resource label in requested capability
    requested = [{"service": "openai", "scopes": ["chat"], "environment": "prod", "resource": resource, "mode": "proxy_only"}]

    session = client.post("/avp/agent_hello", token=agent_token, json={
        "avp_version": "1.0",
        "type": "agent_hello",
        "agent_id": agent_id,
        "agent_version": "0.1.0",
        "runtime": "cli",
        "metadata": {},
        "requested_capabilities": requested
    })
    session_token = session["session_token"]
    session_id = session["session_id"]
    handle = (session.get("capability_handles") or {}).get("openai")
    if not handle:
        raise RuntimeError("no capability handle returned for openai")

    result = client.post("/avp/proxy_call", token=session_token, json={
        "avp_version": "1.0",
        "type": "proxy_call",
        "session_id": session_id,
        "capability_handle": handle,
        "operation": "chat",
        "payload": {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2
        }
    })
    print(result)

@app.command()
def run(
    agent_id: str = typer.Option(...),
    capabilities_file: Optional[str] = typer.Option(None, help="Path to JSON list of capabilities"),
    resource: Optional[str] = typer.Option("default", help="Secret label (resource) to use when no capabilities_file is provided."),
    command: List[str] = typer.Argument(..., help="Command to run after --"),
):
    cfg = load_config()
    url = _require_url(cfg)
    agent_token = os.environ.get("AVP_AGENT_TOKEN") or get_agent_token(cfg, agent_id)
    if not agent_token:
        raise typer.BadParameter("Missing agent token. Run: avp create-agent-token or set AVP_AGENT_TOKEN")

    client = AVPHttpClient(url)
    # AVP-012: Pass resource label for default capabilities
    requested = _load_capabilities(capabilities_file, resource=resource)

    hello = {
        "avp_version": "1.0",
        "type": "agent_hello",
        "agent_id": agent_id,
        "agent_version": "0.1.0",
        "runtime": "cli",
        "metadata": {},
        "requested_capabilities": requested
    }
    session = client.post("/avp/agent_hello", token=agent_token, json=hello)
    session_token = session["session_token"]
    session_id = session["session_id"]

    bundle = client.post("/avp/resolve_secrets", token=session_token, json={
        "avp_version": "1.0",
        "type": "resolve_secrets",
        "session_id": session_id,
        "filters": {"format": "environment"}
    })
    env_secrets = bundle["secrets"]

    env = os.environ.copy()
    for k, v in env_secrets.items():
        env[str(k)] = str(v)

    print("[green]Session created[/green]", session_id)
    print("[green]Injecting env vars[/green]", list(env_secrets.keys()))
    print("[green]Running[/green]", command)

    # Run command
    result = subprocess.run(command, env=env)
    raise typer.Exit(code=result.returncode)


# AVP-050: Capability manifest support
@app.command("agent-template")
def agent_template(
    service: str = typer.Option("openai", help="Service name"),
    scope: str = typer.Option("chat", help="Scope for the capability"),
    environment: str = typer.Option("prod", help="Environment"),
    resource: Optional[str] = typer.Option("default", help="Resource label (secret label)"),
    mode: str = typer.Option("both", help="Mode: secret_resolution, proxy_only, or both"),
    output: Optional[str] = typer.Option(None, help="Output file path (prints to stdout if not set)"),
):
    """Generate a session template JSON for agent configuration.

    Use this to create capability manifests for avp run --capabilities-file.
    """
    template = {
        "allowed_capabilities": [
            {
                "service": service,
                "scopes": [scope],
                "environment": environment,
                "resource": resource,
                "mode": mode
            }
        ],
        "max_session_seconds": 3600
    }

    json_str = json.dumps(template, indent=2)

    if output:
        Path(output).write_text(json_str, encoding="utf-8")
        print(f"[green]Template written to {output}[/green]")
    else:
        print(json_str)


# AVP-051: CLI lifecycle polish commands
@app.command("configure")
def configure(
    url: Optional[str] = typer.Option(None, help="AVP server URL"),
    principal_token: Optional[str] = typer.Option(None, help="Principal token"),
):
    """Configure AVP CLI settings."""
    cfg = load_config()

    if url:
        cfg["url"] = url
        print(f"[green]URL set to:[/green] {url}")

    if principal_token:
        cfg["principal_token"] = principal_token
        print("[green]Principal token saved[/green]")

    if not url and not principal_token:
        print("Current configuration:")
        print(f"  URL: {cfg.get('url', '(not set)')}")
        print(f"  Principal token: {'(set)' if cfg.get('principal_token') else '(not set)'}")
        return

    save_config(cfg)


@app.command("whoami")
def whoami():
    """Show current principal information."""
    cfg = load_config()
    url = cfg.get("url")
    token = cfg.get("principal_token")

    print("AVP CLI Configuration:")
    print(f"  Server URL: {url or '(not set)'}")
    print(f"  Principal token: {'***' + token[-8:] if token and len(token) > 8 else '(not set)'}")

    if not url or not token:
        print("\n[yellow]Configuration incomplete. Run: avp configure --url <url> --principal-token <token>[/yellow]")
        return

    # Try to list agents to verify token works
    try:
        client = AVPHttpClient(url)
        agents = client.get("/agents", token=token)
        print(f"\n[green]Token valid. You have {len(agents)} agents.[/green]")
    except Exception as e:
        print(f"\n[red]Could not verify token: {e}[/red]")


@app.command("status")
def status():
    """Show server connection status and configuration."""
    cfg = load_config()
    url = cfg.get("url")

    print("AVP Status:")
    print(f"  Server URL: {url or '(not configured)'}")

    if not url:
        print("\n[yellow]No server configured. Run: avp configure --url <url>[/yellow]")
        return

    # Check server health
    try:
        client = AVPHttpClient(url)
        # Try to fetch services (unauthenticated)
        services = client.get("/services")
        print(f"  Server status: [green]reachable[/green]")
        print(f"  Available services: {', '.join(services.get('services', {}).keys())}")
    except Exception as e:
        print(f"  Server status: [red]unreachable[/red]")
        print(f"  Error: {e}")

    # Check token
    token = cfg.get("principal_token")
    if token:
        print(f"  Principal token: [green]configured[/green]")
    else:
        print(f"  Principal token: [yellow]not configured[/yellow]")
