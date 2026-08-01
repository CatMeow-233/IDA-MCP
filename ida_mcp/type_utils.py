"""IDA type-system helper functions."""
from __future__ import annotations

from typing import Any


def iter_local_type_ordinals(ida_typeinf_module: Any) -> range:
    """Return the sparse local type ordinal range exposed by IDA 9.x."""
    if ida_typeinf_module is None:
        return range(1, 1)
    try:
        limit = int(ida_typeinf_module.get_ordinal_limit())
    except Exception:
        limit = 1
    if limit <= 1:
        return range(1, 1)
    return range(1, limit)
