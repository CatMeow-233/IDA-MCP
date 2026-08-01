"""State management - instance selection and forwarding."""

from __future__ import annotations

import time
from typing import Optional, Any, List

from ..errors import error_payload, normalize_error_payload
from ._http import http_get, http_post


def get_instances() -> List[dict]:
    """Get the list of all instances."""
    data = http_get("/instances")
    return data if isinstance(data, list) else []


def is_valid_port(p: Any) -> bool:
    """Validate port format (1-65535)."""
    return isinstance(p, int) and 1 <= p <= 65535


def is_registered_port(port: int) -> bool:
    """Check whether the port corresponds to a registered instance."""
    instances = get_instances()
    return any(i.get("port") == port for i in instances)


def get_selected_port() -> Optional[int]:
    """Return the gateway-wide selected instance port, if any."""
    data = http_get("/current_instance")
    if isinstance(data, dict) and is_valid_port(data.get("port")):
        return int(data["port"])
    try:
        from .. import instance_registry as registry

        if is_valid_port(registry._current_instance_port):
            return int(registry._current_instance_port)
    except Exception:
        pass
    return None


def set_selected_port(port: int) -> None:
    """Store the gateway-wide selected instance port."""
    http_post("/select_instance", {"port": int(port)})
    try:
        from .. import instance_registry as registry

        with registry._lock:
            registry._current_instance_port = int(port)
    except Exception:
        pass


def clear_selected_port() -> None:
    """Clear the gateway-wide selected instance port."""
    http_post("/select_instance", {"clear": True})
    try:
        from .. import instance_registry as registry

        with registry._lock:
            registry._current_instance_port = None
    except Exception:
        pass


def _health_rank(instance: dict) -> tuple[int, int, int]:
    health = str(instance.get("effective_state") or instance.get("health") or "")
    quarantined_until = float(instance.get("quarantined_until") or 0.0)
    is_quarantined = 1 if quarantined_until > time.time() else 0
    is_unhealthy = 1 if health in {"unreachable", "unresponsive", "error"} else 0
    preferred_port = 0 if instance.get("port") == 10000 else 1
    return (is_quarantined, is_unhealthy, preferred_port)


def _is_auto_routable(instance: dict) -> bool:
    return str(instance.get("effective_state") or "ready") == "ready"


def choose_port(port: Optional[int] = None) -> Optional[int]:
    """Select target port.

    If port is explicitly provided, only validate its validity.
    If not provided, first use the gateway-selected instance set by
    select_instance. If that selection is gone, auto-select using:
    1. prefer port 10000
    2. otherwise take the smallest registered port
    """
    if port is not None:
        if not is_valid_port(port):
            return None
        return port if is_registered_port(port) else None

    selected_port = get_selected_port()
    instances = get_instances()
    if selected_port is not None:
        if any(i.get("port") == selected_port for i in instances):
            return selected_port
        clear_selected_port()

    instances = [
        i
        for i in instances
        if is_valid_port(i.get("port")) and _is_auto_routable(i)
    ]
    if not instances:
        return None

    instances = sorted(instances, key=lambda i: (_health_rank(i), int(i.get("port"))))
    return int(instances[0].get("port"))


def forward(
    tool: str,
    params: Optional[dict] = None,
    port: Optional[int] = None,
    timeout: Optional[int] = None,
) -> Any:
    """Unified forwarding call to the backend.

    Args:
        tool: tool name
        params: tool parameters
        port: specific port (optional; if omitted, uses the currently selected instance)
        timeout: custom timeout in seconds (optional; if omitted, uses the default)

    Returns:
        tool call result, or an error dict
    """
    # determine target port
    if port is not None:
        # user specified a port; validate it
        if not is_valid_port(port):
            return error_payload(
                "invalid_port",
                f"Invalid port: {port}. Port must be 1-65535.",
                port=port,
            )
        if not is_registered_port(port):
            return error_payload(
                "instance_not_found",
                f"Port {port} not found in registered instances. Use list_instances to check available instances.",
                port=port,
            )
        target_port = port
    else:
        # auto-select port
        target_port = choose_port()
        if target_port is None:
            return error_payload(
                "no_instances",
                "No IDA instances available. Please ensure IDA is running with the MCP plugin loaded.",
            )

    # build request
    body: dict = {"tool": tool, "params": params or {}, "port": int(target_port)}
    if timeout and timeout > 0:
        body["timeout"] = timeout
    # HTTP-layer timeout should be longer than the gateway internal tool timeout to allow margin for lock acquisition + connection setup
    http_timeout = (timeout + 15) if (timeout and timeout > 0) else None
    result = http_post("/call", body, timeout=http_timeout)

    # process result
    if result is None:
        return error_payload(
            "gateway_unavailable",
            "Failed to connect to gateway. Ensure the standalone gateway is running and reachable.",
        )

    # extract actual data
    if isinstance(result, dict):
        if "error" in result:
            return normalize_error_payload(
                result,
                "tool_call_failed",
                f"Gateway rejected proxy call for tool {tool}.",
                tool=tool,
                port=target_port,
            )
        if "data" in result:
            return result["data"]

    return result
