from __future__ import annotations

import os
from typing import Any, Dict, Optional

import httpx

from .models import SessionInfo


class AVPClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    @staticmethod
    def from_env() -> "AVPClient":
        url = os.environ.get("AVP_URL") or os.environ.get("AVP_SERVER_URL") or "http://localhost:8000"
        return AVPClient(url)

    def _url(self, path: str) -> str:
        return self.base_url + path

    def agent_hello(self, agent_token: str, agent_id: str, requested_capabilities: list[dict], metadata: Optional[dict] = None) -> SessionInfo:
        payload = {
            "avp_version": "1.0",
            "type": "agent_hello",
            "agent_id": agent_id,
            "agent_version": "0.1.0",
            "runtime": "python",
            "metadata": metadata or {},
            "requested_capabilities": requested_capabilities
        }
        headers = {"Authorization": f"Bearer {agent_token}"}
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(self._url("/avp/agent_hello"), json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        return SessionInfo(
            session_id=data["session_id"],
            session_token=data["session_token"],
            expires_at=data["expires_at"],
            granted_capabilities=data.get("granted_capabilities") or [],
            capability_handles=data.get("capability_handles") or {}
        )

    def resolve_secrets(self, session_token: str, session_id: str, *, format: str = "environment", services: Optional[list[str]] = None) -> Dict[str, Any]:
        payload = {
            "avp_version": "1.0",
            "type": "resolve_secrets",
            "session_id": session_id,
            "filters": {"format": format, "services": services}
        }
        headers = {"Authorization": f"Bearer {session_token}"}
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(self._url("/avp/resolve_secrets"), json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        return data.get("secrets") or {}

    def proxy_call(self, session_token: str, session_id: str, handle: str, operation: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        body = {
            "avp_version": "1.0",
            "type": "proxy_call",
            "session_id": session_id,
            "capability_handle": handle,
            "operation": operation,
            "payload": payload
        }
        headers = {"Authorization": f"Bearer {session_token}"}
        with httpx.Client(timeout=60.0) as client:
            resp = client.post(self._url("/avp/proxy_call"), json=body, headers=headers)
            resp.raise_for_status()
            return resp.json()

    def proxy_call_stream(self, session_token: str, session_id: str, handle: str, operation: str, payload: Dict[str, Any]):
        """Proxy a streaming call; yields raw SSE lines from the upstream provider.

        Sets stream=true in the payload. Iterate the result to consume the stream:

            for line in client.proxy_call_stream(tok, sid, handle, "chat", {...}):
                ...
        """
        body = {
            "avp_version": "1.0",
            "type": "proxy_call",
            "session_id": session_id,
            "capability_handle": handle,
            "operation": operation,
            "payload": {**payload, "stream": True}
        }
        headers = {"Authorization": f"Bearer {session_token}"}
        with httpx.Client(timeout=httpx.Timeout(300.0, connect=10.0)) as client:
            with client.stream("POST", self._url("/avp/proxy_call"), json=body, headers=headers) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines():
                    yield line

    @staticmethod
    def install_env(env_map: Dict[str, Any]) -> None:
        for k, v in env_map.items():
            os.environ[str(k)] = str(v)
