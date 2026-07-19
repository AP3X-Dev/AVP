from __future__ import annotations

from typing import Any, Dict, Tuple

import httpx

from ..config import settings


async def _openai_post(path: str, secret_data: Dict[str, Any], payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    api_key = secret_data.get("api_key")
    base_url = secret_data.get("base_url") or settings.openai_base_url
    if not api_key:
        return 500, {"error": {"message": "missing api_key in secret", "type": "server_error"}}

    url = base_url.rstrip("/") + path
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    org_id = secret_data.get("org_id")
    if org_id:
        headers["OpenAI-Organization"] = str(org_id)

    timeout = httpx.Timeout(60.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, headers=headers, json=payload)
        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text}
        return resp.status_code, data


async def openai_chat_completion(secret_data: Dict[str, Any], payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    return await _openai_post("/chat/completions", secret_data, payload)


async def openai_embeddings(secret_data: Dict[str, Any], payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    return await _openai_post("/embeddings", secret_data, payload)
