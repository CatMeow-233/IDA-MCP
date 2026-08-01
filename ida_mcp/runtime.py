"""Runtime helpers that coordinate the standalone gateway."""
from __future__ import annotations


def start_gateway_proxy_if_enabled() -> str | None:
    """Ensure the client-facing gateway MCP proxy is running when enabled."""
    from . import registry
    from .config import get_http_url, is_gateway_enabled

    if not is_gateway_enabled():
        return None

    if registry.ensure_gateway_proxy_running():
        return get_http_url()

    return None
