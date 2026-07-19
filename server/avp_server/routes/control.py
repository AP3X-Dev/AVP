from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import secrets as pysecrets
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..config import settings
from ..deps import get_conn, require_principal
from ..db import execute, fetchone, fetchall
from ..auth import new_token, token_sha256, hash_token
from ..crypto import encrypt_json, current_key_version
from ..audit import audit_event
from ..services.registry import get_service_spec, SecretValidationError, get_registry_info, list_services

router = APIRouter(prefix="", tags=["control"])


class DevBootstrapRequest(BaseModel):
    email: str
    display_name: str = "User"


class DevBootstrapResponse(BaseModel):
    principal_id: int
    principal_token: str


@router.post("/dev/bootstrap_principal", response_model=DevBootstrapResponse)
def dev_bootstrap_principal(req: DevBootstrapRequest, request: Request, conn=Depends(get_conn)):
    """Create a principal in dev mode only.

    AVP-041: This endpoint returns 404 when AVP_DEV_MODE=false.
    Use /admin/bootstrap_principal with AVP_ADMIN_BOOTSTRAP_TOKEN for production.
    """
    if not settings.dev_mode:
        raise HTTPException(status_code=404, detail="not found")

    return _create_principal(req.email, req.display_name, request, conn)


class AdminBootstrapRequest(BaseModel):
    """Request for admin bootstrap endpoint."""
    email: str
    display_name: str = "Admin"
    token: str  # Must match AVP_ADMIN_BOOTSTRAP_TOKEN


@router.post("/admin/bootstrap_principal", response_model=DevBootstrapResponse)
def admin_bootstrap_principal(req: AdminBootstrapRequest, request: Request, conn=Depends(get_conn)):
    """Create the first principal using a one-time admin token.

    AVP-040: This endpoint is only available when AVP_ADMIN_BOOTSTRAP_TOKEN is set.
    After bootstrap, remove the token from environment to disable this endpoint.

    Security:
    - Token must match AVP_ADMIN_BOOTSTRAP_TOKEN exactly
    - Endpoint is disabled (404) when token is not configured
    - Use a strong, random token for production bootstrap
    """
    # Endpoint only available when admin token is configured
    if not settings.admin_bootstrap_token:
        raise HTTPException(status_code=404, detail="not found")

    if not pysecrets.compare_digest(req.token, settings.admin_bootstrap_token):
        raise HTTPException(status_code=403, detail="invalid bootstrap token")

    return _create_principal(req.email, req.display_name, request, conn)


def _create_principal(email: str, display_name: str, request: Request, conn) -> DevBootstrapResponse:
    """Create or get a principal and generate a token.

    Shared logic for both dev and admin bootstrap endpoints.
    """
    existing = fetchone(conn, "SELECT id FROM principals WHERE email = %s", [email])
    if existing:
        principal_id = existing["id"]
    else:
        execute(conn, "INSERT INTO principals (email, display_name) VALUES (%s, %s)", [email, display_name])
        row = fetchone(conn, "SELECT id FROM principals WHERE email = %s", [email])
        principal_id = row["id"]

    token = new_token("ptk_")
    sha = token_sha256(token)
    th = hash_token(token)

    execute(conn, """
        INSERT INTO api_tokens (principal_id, agent_id, token_sha256, token_hash, token_type, scopes, session_template, expires_at)
        VALUES (%s, NULL, %s, %s, 'principal', '[]'::jsonb, '{}'::jsonb, NULL)
    """, [principal_id, sha, th])

    audit_event(conn, principal_id=principal_id, agent_db_id=None, session_db_id=None, session_id=None,
                event_type="token_created", metadata={"token_type": "principal"}, ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"))
    conn.commit()
    return DevBootstrapResponse(principal_id=principal_id, principal_token=token)


class CreateAgentRequest(BaseModel):
    agent_id: str
    name: str
    description: Optional[str] = None
    default_policy: Dict[str, Any] = Field(default_factory=dict)


class CreateAgentResponse(BaseModel):
    agent_db_id: int
    agent_id: str


@router.post("/agents", response_model=CreateAgentResponse)
def create_agent(req: CreateAgentRequest, request: Request, principal=Depends(require_principal), conn=Depends(get_conn)):
    pid = principal["principal_id"]
    exists = fetchone(conn, "SELECT id FROM agents WHERE principal_id = %s AND agent_id = %s", [pid, req.agent_id])
    if exists:
        raise HTTPException(status_code=409, detail="agent already exists")

    execute(conn, """
        INSERT INTO agents (principal_id, agent_id, name, description, default_policy)
        VALUES (%s, %s, %s, %s, %s::jsonb)
    """, [pid, req.agent_id, req.name, req.description, json.dumps(req.default_policy)])

    row = fetchone(conn, "SELECT id FROM agents WHERE principal_id = %s AND agent_id = %s", [pid, req.agent_id])
    aid = row["id"]
    audit_event(conn, principal_id=pid, agent_db_id=aid, session_db_id=None, session_id=None,
                event_type="agent_created", metadata={"agent_id": req.agent_id}, ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"))
    conn.commit()
    return CreateAgentResponse(agent_db_id=aid, agent_id=req.agent_id)


class AgentListItem(BaseModel):
    agent_db_id: int
    agent_id: str
    name: str
    description: Optional[str] = None
    created_at: str


@router.get("/agents", response_model=List[AgentListItem])
def list_agents(principal=Depends(require_principal), conn=Depends(get_conn)):
    pid = principal["principal_id"]
    rows = fetchall(conn, """
        SELECT id, agent_id, name, description, created_at
        FROM agents
        WHERE principal_id = %s
        ORDER BY created_at DESC
    """, [pid])
    return [AgentListItem(
        agent_db_id=r["id"],
        agent_id=r["agent_id"],
        name=r["name"],
        description=r["description"],
        created_at=r["created_at"].isoformat(),
    ) for r in rows]


class CreateAgentTokenRequest(BaseModel):
    # session_template overrides agent default_policy if provided
    session_template: Optional[Dict[str, Any]] = None
    expires_in_seconds: Optional[int] = None


class CreateAgentTokenResponse(BaseModel):
    agent_id: str
    token: str


@router.post("/agents/{agent_id}/tokens", response_model=CreateAgentTokenResponse)
def create_agent_token(agent_id: str, req: CreateAgentTokenRequest, request: Request, principal=Depends(require_principal), conn=Depends(get_conn)):
    pid = principal["principal_id"]
    agent = fetchone(conn, "SELECT id, default_policy FROM agents WHERE principal_id = %s AND agent_id = %s", [pid, agent_id])
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")

    token = new_token("agt_")
    sha = token_sha256(token)
    th = hash_token(token)

    st = req.session_template if req.session_template is not None else (agent["default_policy"] or {})
    expires_at = None
    if req.expires_in_seconds:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=req.expires_in_seconds)

    execute(conn, """
        INSERT INTO api_tokens (principal_id, agent_id, token_sha256, token_hash, token_type, scopes, session_template, expires_at)
        VALUES (%s, %s, %s, %s, 'agent', '[]'::jsonb, %s::jsonb, %s)
    """, [pid, agent["id"], sha, th, json.dumps(st), expires_at])

    audit_event(conn, principal_id=pid, agent_db_id=agent["id"], session_db_id=None, session_id=None,
                event_type="token_created", metadata={"token_type": "agent", "agent_id": agent_id}, ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"))
    conn.commit()
    return CreateAgentTokenResponse(agent_id=agent_id, token=token)


class TokenListItem(BaseModel):
    token_id: int
    token_type: str
    agent_id: Optional[str] = None
    created_at: str
    expires_at: Optional[str] = None
    revoked_at: Optional[str] = None


@router.get("/tokens", response_model=List[TokenListItem])
def list_tokens(principal=Depends(require_principal), conn=Depends(get_conn)):
    """List API tokens for the authenticated principal (metadata only, never the token)."""
    pid = principal["principal_id"]
    rows = fetchall(conn, """
        SELECT t.id, t.token_type, a.agent_id, t.created_at, t.expires_at, t.revoked_at
        FROM api_tokens t
        LEFT JOIN agents a ON a.id = t.agent_id
        WHERE t.principal_id = %s
        ORDER BY t.created_at DESC
    """, [pid])
    return [TokenListItem(
        token_id=r["id"],
        token_type=r["token_type"],
        agent_id=r["agent_id"],
        created_at=r["created_at"].isoformat(),
        expires_at=r["expires_at"].isoformat() if r["expires_at"] else None,
        revoked_at=r["revoked_at"].isoformat() if r["revoked_at"] else None,
    ) for r in rows]


class RevokeTokenRequest(BaseModel):
    reason: str = "revoked"


@router.post("/tokens/{token_id}/revoke")
def revoke_token(token_id: int, req: RevokeTokenRequest, request: Request, principal=Depends(require_principal), conn=Depends(get_conn)):
    """Revoke an API token. Revoked tokens fail authentication immediately."""
    pid = principal["principal_id"]
    row = fetchone(conn, "SELECT id, token_type, revoked_at FROM api_tokens WHERE id = %s AND principal_id = %s", [token_id, pid])
    if not row:
        raise HTTPException(status_code=404, detail="token not found")
    if row["revoked_at"] is not None:
        return {"ok": True, "already_revoked": True}

    # A principal must not lock itself out by revoking the token it is using
    if row["id"] == principal["id"]:
        raise HTTPException(status_code=400, detail="cannot revoke the token used for this request")

    execute(conn, "UPDATE api_tokens SET revoked_at = now(), revoked_reason = %s WHERE id = %s", [req.reason, token_id])
    audit_event(conn, principal_id=pid, agent_db_id=None, session_db_id=None, session_id=None,
                event_type="token_revoked", metadata={"token_id": token_id, "token_type": row["token_type"], "reason": req.reason},
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"))
    conn.commit()
    return {"ok": True}


class UpsertSecretRequest(BaseModel):
    service_name: str
    label: str
    environment: str = "prod"
    data: Dict[str, Any]
    meta: Dict[str, Any] = Field(default_factory=dict)


class SecretMetaResponse(BaseModel):
    service_name: str
    label: str
    environment: str
    updated_at: str


@router.post("/secrets", response_model=SecretMetaResponse)
def upsert_secret(req: UpsertSecretRequest, request: Request, principal=Depends(require_principal), conn=Depends(get_conn)):
    pid = principal["principal_id"]

    # AVP-030: Validate secret data against service schema
    spec = get_service_spec(req.service_name)
    if not spec:
        raise HTTPException(status_code=400, detail={"error": f"unknown service: {req.service_name}"})

    try:
        spec.validate_secret(req.data, allow_extra=settings.allow_extra_secret_fields)
    except SecretValidationError as e:
        raise HTTPException(status_code=400, detail={
            "error": "secret_validation_failed",
            "message": e.message,
            "field": e.field
        })

    # Look up without the deleted filter: re-adding a soft-deleted secret must
    # revive the existing row, or the unique constraint rejects the INSERT.
    secret = fetchone(conn, """
        SELECT id, deleted_at FROM secrets
        WHERE principal_id = %s AND service_name = %s AND label = %s AND environment = %s
    """, [pid, req.service_name, req.label, req.environment])

    if secret and secret["deleted_at"] is not None:
        execute(conn, "UPDATE secrets SET deleted_at = NULL WHERE id = %s", [secret["id"]])

    if not secret:
        execute(conn, """
            INSERT INTO secrets (principal_id, service_name, label, environment, meta)
            VALUES (%s, %s, %s, %s, %s::jsonb)
        """, [pid, req.service_name, req.label, req.environment, json.dumps(req.meta)])
        secret = fetchone(conn, """
            SELECT id FROM secrets
            WHERE principal_id = %s AND service_name = %s AND label = %s AND environment = %s AND deleted_at IS NULL
        """, [pid, req.service_name, req.label, req.environment])

    secret_id = secret["id"]

    # versioning
    current = fetchone(conn, "SELECT version FROM secret_versions WHERE secret_id = %s ORDER BY version DESC LIMIT 1", [secret_id])
    next_version = (current["version"] + 1) if current else 1

    # mark prior current false
    execute(conn, "UPDATE secret_versions SET is_current = FALSE WHERE secret_id = %s AND is_current = TRUE", [secret_id])

    blob = encrypt_json(req.data)
    execute(conn, """
        INSERT INTO secret_versions (secret_id, version, data_ciphertext, key_version, created_by, is_current)
        VALUES (%s, %s, %s, %s, %s, TRUE)
    """, [secret_id, next_version, blob, current_key_version(), pid])

    execute(conn, "UPDATE secrets SET updated_at = now(), meta = %s::jsonb WHERE id = %s", [json.dumps(req.meta), secret_id])

    audit_event(conn, principal_id=pid, agent_db_id=None, session_db_id=None, session_id=None,
                event_type="secret_updated", service_name=req.service_name,
                metadata={"label": req.label, "environment": req.environment, "version": next_version},
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"))
    conn.commit()

    meta = fetchone(conn, "SELECT updated_at FROM secrets WHERE id = %s", [secret_id])
    return SecretMetaResponse(service_name=req.service_name, label=req.label, environment=req.environment, updated_at=meta["updated_at"].isoformat())


@router.get("/secrets", response_model=List[SecretMetaResponse])
def list_secrets(principal=Depends(require_principal), conn=Depends(get_conn)):
    pid = principal["principal_id"]
    rows = fetchall(conn, """
        SELECT service_name, label, environment, updated_at
        FROM secrets
        WHERE principal_id = %s AND deleted_at IS NULL
        ORDER BY updated_at DESC
    """, [pid])
    return [SecretMetaResponse(service_name=r["service_name"], label=r["label"], environment=r["environment"], updated_at=r["updated_at"].isoformat()) for r in rows]


def _find_secret(conn, pid: int, service_name: str, label: str, environment: str):
    secret = fetchone(conn, """
        SELECT id FROM secrets
        WHERE principal_id = %s AND service_name = %s AND label = %s AND environment = %s AND deleted_at IS NULL
    """, [pid, service_name, label, environment])
    if not secret:
        raise HTTPException(status_code=404, detail="secret not found")
    return secret


class SecretVersionItem(BaseModel):
    version: int
    key_version: str
    is_current: bool
    created_at: str


@router.get("/secrets/versions", response_model=List[SecretVersionItem])
def list_secret_versions(service_name: str, label: str, environment: str = "prod", principal=Depends(require_principal), conn=Depends(get_conn)):
    """List a secret's version history (metadata only, never the data)."""
    pid = principal["principal_id"]
    secret = _find_secret(conn, pid, service_name, label, environment)
    rows = fetchall(conn, """
        SELECT version, key_version, is_current, created_at
        FROM secret_versions
        WHERE secret_id = %s
        ORDER BY version DESC
    """, [secret["id"]])
    return [SecretVersionItem(
        version=r["version"],
        key_version=r["key_version"],
        is_current=r["is_current"],
        created_at=r["created_at"].isoformat(),
    ) for r in rows]


class RollbackSecretRequest(BaseModel):
    service_name: str
    label: str
    environment: str = "prod"
    version: int


@router.post("/secrets/rollback", response_model=SecretMetaResponse)
def rollback_secret(req: RollbackSecretRequest, request: Request, principal=Depends(require_principal), conn=Depends(get_conn)):
    """Roll a secret back to an earlier version.

    Appends a new version carrying the old ciphertext (history stays intact)
    rather than flipping is_current on the old row.
    """
    pid = principal["principal_id"]
    secret = _find_secret(conn, pid, req.service_name, req.label, req.environment)
    secret_id = secret["id"]

    target = fetchone(conn, """
        SELECT version, data_ciphertext, key_version, is_current
        FROM secret_versions
        WHERE secret_id = %s AND version = %s
    """, [secret_id, req.version])
    if not target:
        raise HTTPException(status_code=404, detail=f"version {req.version} not found")

    if not target["is_current"]:
        latest = fetchone(conn, "SELECT version FROM secret_versions WHERE secret_id = %s ORDER BY version DESC LIMIT 1", [secret_id])
        next_version = latest["version"] + 1

        execute(conn, "UPDATE secret_versions SET is_current = FALSE WHERE secret_id = %s AND is_current = TRUE", [secret_id])
        execute(conn, """
            INSERT INTO secret_versions (secret_id, version, data_ciphertext, key_version, created_by, is_current)
            VALUES (%s, %s, %s, %s, %s, TRUE)
        """, [secret_id, next_version, target["data_ciphertext"], target["key_version"], pid])
        execute(conn, "UPDATE secrets SET updated_at = now() WHERE id = %s", [secret_id])

        audit_event(conn, principal_id=pid, agent_db_id=None, session_db_id=None, session_id=None,
                    event_type="secret_rolled_back", service_name=req.service_name,
                    metadata={"label": req.label, "environment": req.environment,
                              "from_version": req.version, "new_version": next_version},
                    ip_address=request.client.host if request.client else None,
                    user_agent=request.headers.get("user-agent"))
        conn.commit()

    meta = fetchone(conn, "SELECT updated_at FROM secrets WHERE id = %s", [secret_id])
    return SecretMetaResponse(service_name=req.service_name, label=req.label, environment=req.environment, updated_at=meta["updated_at"].isoformat())


@router.delete("/secrets")
def delete_secret(service_name: str, label: str, environment: str = "prod", request: Request = None, principal=Depends(require_principal), conn=Depends(get_conn)):
    """Soft-delete a secret. Its versions are retained but it can no longer be resolved."""
    pid = principal["principal_id"]
    secret = _find_secret(conn, pid, service_name, label, environment)

    execute(conn, "UPDATE secrets SET deleted_at = now() WHERE id = %s", [secret["id"]])
    audit_event(conn, principal_id=pid, agent_db_id=None, session_db_id=None, session_id=None,
                event_type="secret_deleted", service_name=service_name,
                metadata={"label": label, "environment": environment},
                ip_address=request.client.host if request and request.client else None,
                user_agent=request.headers.get("user-agent") if request else None)
    conn.commit()
    return {"ok": True}


class AuditLogItem(BaseModel):
    event_type: str
    service_name: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str


@router.get("/audit", response_model=List[AuditLogItem])
def list_audit_logs(
    event_type: Optional[str] = None,
    session_id: Optional[str] = None,
    limit: int = 100,
    principal=Depends(require_principal),
    conn=Depends(get_conn),
):
    """List audit log entries for the authenticated principal, newest first."""
    pid = principal["principal_id"]
    limit = max(1, min(limit, 500))

    query = """
        SELECT event_type, service_name, session_id, request_id, metadata, created_at
        FROM audit_logs
        WHERE principal_id = %s
    """
    params: List[Any] = [pid]
    if event_type:
        query += " AND event_type = %s"
        params.append(event_type)
    if session_id:
        query += " AND session_id = %s"
        params.append(session_id)
    query += " ORDER BY created_at DESC, id DESC LIMIT %s"
    params.append(limit)

    rows = fetchall(conn, query, params)
    return [AuditLogItem(
        event_type=r["event_type"],
        service_name=r["service_name"],
        session_id=r["session_id"],
        request_id=r["request_id"],
        metadata=r["metadata"] or {},
        created_at=r["created_at"].isoformat(),
    ) for r in rows]


class SessionListItem(BaseModel):
    session_id: str
    agent_id: str
    created_at: str
    expires_at: str
    revoked_at: Optional[str] = None


@router.get("/sessions", response_model=List[SessionListItem])
def list_sessions(principal=Depends(require_principal), conn=Depends(get_conn)):
    pid = principal["principal_id"]
    rows = fetchall(conn, """
        SELECT s.session_id, s.agent_logical_id as agent_id, s.created_at, s.expires_at, s.revoked_at
        FROM sessions s
        WHERE s.principal_id = %s
        ORDER BY s.created_at DESC
        LIMIT 200
    """, [pid])
    out = []
    for r in rows:
        out.append(SessionListItem(
            session_id=r["session_id"],
            agent_id=r["agent_id"],
            created_at=r["created_at"].isoformat(),
            expires_at=r["expires_at"].isoformat(),
            revoked_at=r["revoked_at"].isoformat() if r["revoked_at"] else None
        ))
    return out


class RevokeSessionRequest(BaseModel):
    reason: str = "revoked"


@router.post("/sessions/{session_id}/revoke")
def revoke_session(session_id: str, req: RevokeSessionRequest, request: Request, principal=Depends(require_principal), conn=Depends(get_conn)):
    pid = principal["principal_id"]
    sess = fetchone(conn, "SELECT id, agent_id FROM sessions WHERE principal_id = %s AND session_id = %s", [pid, session_id])
    if not sess:
        raise HTTPException(status_code=404, detail="session not found")
    execute(conn, "UPDATE sessions SET revoked_at = now(), revoked_reason = %s WHERE id = %s", [req.reason, sess["id"]])
    audit_event(conn, principal_id=pid, agent_db_id=sess["agent_id"], session_db_id=sess["id"], session_id=session_id,
                event_type="session_revoked", metadata={"reason": req.reason},
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"))
    conn.commit()
    return {"ok": True}


# AVP-031: Service registry discovery endpoint
@router.get("/services")
def get_services():
    """List all supported services and their metadata.

    This endpoint allows agents to discover what services are available
    and what credentials/operations they support.
    """
    return get_registry_info()
