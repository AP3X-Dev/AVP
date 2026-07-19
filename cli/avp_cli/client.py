from __future__ import annotations

from typing import Any, Dict, Optional

import httpx


class AVPHttpClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def _url(self, path: str) -> str:
        return self.base_url + path

    def post(self, path: str, json: Dict[str, Any], token: Optional[str] = None) -> Dict[str, Any]:
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(self._url(path), json=json, headers=headers)
            try:
                data = resp.json()
            except Exception:
                data = {"raw": resp.text}
            if resp.status_code >= 400:
                raise RuntimeError(f"HTTP {resp.status_code}: {data}")
            return data

    def delete(self, path: str, token: Optional[str] = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        with httpx.Client(timeout=30.0) as client:
            resp = client.delete(self._url(path), headers=headers, params=params)
            try:
                data = resp.json()
            except Exception:
                data = {"raw": resp.text}
            if resp.status_code >= 400:
                raise RuntimeError(f"HTTP {resp.status_code}: {data}")
            return data

    def get(self, path: str, token: Optional[str] = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(self._url(path), headers=headers, params=params)
            try:
                data = resp.json()
            except Exception:
                data = {"raw": resp.text}
            if resp.status_code >= 400:
                raise RuntimeError(f"HTTP {resp.status_code}: {data}")
            return data
