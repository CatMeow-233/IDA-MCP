"""Shared analysis utilities for decompilation helpers."""
from __future__ import annotations

from typing import Any, Optional

# IDA module imports
try:
    import ida_auto  # type: ignore
    import ida_hexrays  # type: ignore
    import ida_kernwin  # type: ignore
except ImportError:
    ida_auto = None
    ida_hexrays = None
    ida_kernwin = None


def _failure_description(failure: Any) -> Optional[str]:
    try:
        desc = failure.desc()
        if desc:
            return str(desc)
    except Exception:
        pass
    return None


def decompile_with_error(ea: int) -> tuple[Any, Optional[str]]:
    """Decompile with dialog suppression and a diagnostic error string."""
    if ida_hexrays is None:
        return None, "ida_hexrays unavailable"

    old_query_graph = None
    old_batch = None
    set_query_graph = getattr(ida_auto, "set_query_graph", None) if ida_auto else None
    kernwin_cvar = getattr(ida_kernwin, "cvar", None) if ida_kernwin else None
    try:
        if kernwin_cvar is not None and hasattr(kernwin_cvar, "batch"):
            old_batch = kernwin_cvar.batch
            kernwin_cvar.batch = 1
        if callable(set_query_graph):
            old_query_graph = set_query_graph(0)
        failure = None
        try:
            failure = ida_hexrays.hexrays_failure_t()  # type: ignore[union-attr]
            cfunc = ida_hexrays.decompile(ea, failure)  # type: ignore[union-attr]
        except TypeError:
            cfunc = ida_hexrays.decompile(ea)  # type: ignore[union-attr]
        if cfunc:
            return cfunc, None
        if failure is not None:
            desc = _failure_description(failure)
            if desc:
                return None, desc
        return None, "decompile returned None"
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"
    finally:
        if callable(set_query_graph) and old_query_graph is not None:
            try:
                set_query_graph(old_query_graph)
            except Exception:
                pass
        if kernwin_cvar is not None and old_batch is not None:
            try:
                kernwin_cvar.batch = old_batch
            except Exception:
                pass


def decompile_silent(ea: int) -> Any:
    """Decompile with dialog suppression (segment read-only warnings, etc.)."""
    cfunc, _error = decompile_with_error(ea)
    return cfunc
