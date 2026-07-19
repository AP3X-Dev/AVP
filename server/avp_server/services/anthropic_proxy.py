from __future__ import annotations

from typing import Any, Dict, Tuple

import httpx

from ..config import settings

ANTHROPIC_VERSION = "2023-06-01"


async def anthropic_messages(secret_data: Dict[str, Any], payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    api_key = secret_data.get("api_key")
    base_url = secret_data.get("base_url") or settings.anthropic_base_url
    if not api_key:
        return 500, {"error": {"message": "missing api_key in secret", "type": "server_error"}}

    url = base_url.rstrip("/") + "/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": ANTHROPIC_VERSION,
        "Content-Type": "application/json",
    }

    timeout = httpx.Timeout(60.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, headers=headers, json=payload)
        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text}
        return resp.status_code, data
