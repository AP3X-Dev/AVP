from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

import httpx

from ..config import settings

ANTHROPIC_VERSION = "2023-06-01"


def anthropic_messages_target(secret_data: Dict[str, Any]) -> Optional[Tuple[str, Dict[str, str]]]:
    """Build (url, headers) for an Anthropic Messages request, or None if the secret has no api_key."""
    api_key = secret_data.get("api_key")
    if not api_key:
        return None
    base_url = secret_data.get("base_url") or settings.anthropic_base_url
    headers = {
        "x-api-key": api_key,
        "anthropic-version": ANTHROPIC_VERSION,
        "Content-Type": "application/json",
    }
    return base_url.rstrip("/") + "/v1/messages", headers


async def anthropic_messages(secret_data: Dict[str, Any], payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    target = anthropic_messages_target(secret_data)
    if target is None:
        return 500, {"error": {"message": "missing api_key in secret", "type": "server_error"}}
    url, headers = target

    timeout = httpx.Timeout(60.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, headers=headers, json=payload)
        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text}
        return resp.status_code, data
