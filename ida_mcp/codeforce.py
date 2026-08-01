"""Force-decode helpers for ranges IDA never analyzed (shell/VM/JIT buffers).

Two complementary strategies:

1. ``force_code_range`` — IDB mutation: linear sweep over [start, end),
   undefining the covering item and ``create_insn`` at each head; bytes that
   refuse to decode are skipped one at a time.  After this, the normal
   tools (disasm_text / decompile / compress_range) work on the range.
   Caller must hold write access (@idawrite).

2. ``capstone_disasm_range`` — pure-read byte-level fallback: decode raw
   bytes with capstone without touching the IDB.  Used by disasm_text /
   linear_disasm when the IDB has no instructions for the range.
   Capstone is lazy-imported (ships with IDA 9.x python); a clear error is
   returned when it is missing.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .rpc import tool
from .sync import idawrite
from .utils import hex_addr

try:
    import ida_bytes  # type: ignore
    import ida_ida  # type: ignore
    import ida_ua  # type: ignore
except ImportError:
    ida_bytes = None
    ida_ida = None
    ida_ua = None

# Single sweep over a huge buffer must stay responsive; mirror the modeling cap.
_MAX_FORCE_RANGE = 0x100000  # 1 MiB


def _detect_arch() -> str:
    """Return 'x64' | 'x86' | 'arm64' | 'arm' from the current IDB."""
    procname: Optional[str] = None
    is64: Optional[bool] = None

    if ida_ida is not None:
        try:
            raw = ida_ida.inf_get_procname()
            if isinstance(raw, bytes):
                raw = raw.decode(errors="ignore")
            procname = raw or None
        except Exception:
            pass
        try:
            is64 = bool(ida_ida.inf_is_64bit())
        except Exception:
            pass

    if procname and "ARM" in procname.upper():
        return "arm64" if is64 else "arm"
    if is64 is not None:
        return "x64" if is64 else "x86"
    return "x64"


@tool
@idawrite
def force_code_range(start: int, end: int) -> Dict[str, Any]:
    """Linear-sweep [start, end) into code inside the IDB.

    At each head: if not code, undefine the covering item and create_insn.
    On decode failure skip one byte (garbage between valid blobs is common
    in unpacked/JIT buffers).  Returns counts plus the first failure, if any.
    """
    if ida_bytes is None or ida_ua is None:
        return {"error": "IDA SDK not available"}
    if end <= start:
        return {"error": "end must be greater than start"}
    if end - start > _MAX_FORCE_RANGE:
        return {"error": "range too large", "max_size": _MAX_FORCE_RANGE}

    made = 0
    skipped = 0
    first_fail: Optional[int] = None
    ea = start
    while ea < end:
        try:
            flags = ida_bytes.get_full_flags(ea)
            if ida_bytes.is_code(flags):
                nxt = int(ida_bytes.next_head(ea, end))
                if nxt <= ea or nxt >= end:
                    break
                ea = nxt
                continue

            head = int(ida_bytes.get_item_head(ea))
            size = int(ida_bytes.get_item_size(head)) or 1
            try:
                ida_bytes.del_items(head, getattr(ida_bytes, "DELIT_SIMPLE", 0), size)
            except Exception:
                pass

            created = 0
            try:
                created = int(ida_ua.create_insn(ea))
            except Exception:
                created = 0

            if created > 0:
                made += 1
                ea += created
            else:
                skipped += 1
                if first_fail is None:
                    first_fail = ea
                ea += 1
        except Exception:
            skipped += 1
            if first_fail is None:
                first_fail = ea
            ea += 1

    result: Dict[str, Any] = {
        "start_ea": hex_addr(start),
        "end_ea": hex_addr(end),
        "instructions_created": made,
        "bytes_skipped": skipped,
    }
    if first_fail is not None:
        result["first_undecodable"] = hex_addr(first_fail)
    if made == 0:
        result["error"] = "no instructions could be created"
    return result


def _capstone_for_arch(arch: str):
    """Return (Cs, mode) for arch, or None when capstone is unavailable."""
    try:
        import capstone  # type: ignore
    except ImportError:
        return None

    table = {
        "x64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        "arm": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
    }
    spec = table.get(arch)
    if spec is None:
        return None
    cs_arch, cs_mode = spec
    return capstone.Cs(cs_arch, cs_mode)


def capstone_disasm_range(
    start: int,
    data: bytes,
    arch: str = "auto",
    max_instructions: int = 100000,
) -> Dict[str, Any]:
    """Decode raw bytes with capstone — no IDB mutation.

    Returns {"arch", "instructions": [{ea, bytes, text}], "truncated"} or
    {"error": ...}.  Undecodable bytes are skipped one at a time.
    """
    if arch == "auto":
        arch = _detect_arch()
    md = _capstone_for_arch(arch)
    if md is None:
        return {"error": "capstone not available for arch", "arch": arch}

    instructions: List[Dict[str, Any]] = []
    offset = 0
    size = len(data)
    truncated = False
    while offset < size:
        if len(instructions) >= max_instructions:
            truncated = True
            break
        decoded = None
        for insn in md.disasm(data[offset:], start + offset, count=1):
            decoded = insn
            break
        if decoded is None:
            offset += 1
            continue
        instructions.append({
            "ea": int(decoded.address),
            "bytes": bytes(decoded.bytes).hex().upper(),
            "text": f"{decoded.mnemonic} {decoded.op_str}".strip(),
        })
        offset += max(1, int(decoded.size))

    if not instructions:
        return {"error": "capstone decoded nothing", "arch": arch}
    return {
        "arch": arch,
        "instructions": instructions,
        "truncated": truncated,
    }
