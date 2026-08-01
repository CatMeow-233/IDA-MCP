"""HTTP helpers for communicating with the standalone gateway."""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

from ..config import get_gateway_auth_headers, get_gateway_internal_url, get_request_timeout
from ..registry import ensure_registry_server

_log = logging.getLogger(__name__)


def _parse_response_body(exc: urllib.error.HTTPError) -> Any:
    """Try to extract structured JSON from an HTTP error response."""
    try:
        body = exc.read().decode("utf-8", errors="replace")
        if body:
            return json.loads(body)
    except Exception:
        pass
    return {"error": f"HTTP {exc.code}: {exc.reason}"}


def http_get(path: str) -> Any:
    """GET request against the gateway internal API."""
    if not ensure_registry_server():
        return None
    try:
        req = urllib.request.Request(
            get_gateway_internal_url() + path,
            method="GET",
            headers=get_gateway_auth_headers(),
        )
        with urllib.request.urlopen(req, timeout=get_request_timeout()) as r:
            return json.loads(r.read().decode('utf-8') or 'null')
    except urllib.error.HTTPError as exc:
        _log.debug("GET %s returned HTTP %s", path, exc.code)
        return _parse_response_body(exc)
    except Exception as exc:
        _log.debug("GET %s failed: %s", path, exc)
        return None


def http_post(path: str, obj: dict, timeout: int | None = None) -> Any:
    """POST request against the gateway internal API."""
    if not ensure_registry_server():
        return {"error": "Gateway unavailable"}
    data = json.dumps(obj).encode('utf-8')
    headers = get_gateway_auth_headers()
    headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        get_gateway_internal_url() + path,
        data=data,
        method='POST',
        headers=headers,
    )
    effective_timeout = timeout if timeout and timeout > 0 else get_request_timeout()
    try:
        with urllib.request.urlopen(req, timeout=effective_timeout) as r:
            return json.loads(r.read().decode('utf-8') or 'null')
    except urllib.error.HTTPError as exc:
        _log.debug("POST %s returned HTTP %s", path, exc.code)
        return _parse_response_body(exc)
    except Exception as e:
        return {"error": str(e)}
