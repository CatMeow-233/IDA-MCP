"""Emulation API - Unicorn-based code emulation and decompressor dumping.

Provides tools:
    - emu_run    emulate arbitrary code with the IDB segments as memory image
    - emu_call   call a function under an ABI preset and dump its output buffer

Core rule (see instructor/SHELL_PLAYBOOK.md): emulate, never hand-translate.
Write-watch shows where plaintext lands - algorithm-agnostic. Hand-written
translators are the last resort with a 2-hour cap.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
from typing import Annotated, Any, Dict, List, Optional, Union

from .rpc import tool
from .sync import idaread
from .utils import parse_address, hex_addr, normalize_list_input, normalize_arch
from . import blobscan
from .api_shell import detect_format

from .emu.runner import run as _core_run
from .emu.runner import available as _emu_available
from .emu.runner import ABI_PRESETS as _ABI_PRESETS

try:
    import idc  # type: ignore
    import idautils  # type: ignore
    import ida_bytes  # type: ignore
    import ida_ida  # type: ignore
    import ida_segment  # type: ignore
except ImportError:
    idc = idautils = ida_bytes = ida_ida = ida_segment = None  # type: ignore

_IMAGE_CAP = 256 * 1024 * 1024   # max total memory image built from the IDB
_IN_BASE = 0x40000000
_OUT_BASE = 0x50000000


# ============================================================================
# Helpers
# ============================================================================

def _require_ida() -> Optional[dict]:
    if ida_bytes is None or ida_segment is None:
        return {"error": "IDA runtime unavailable"}
    return None


def _arch_auto() -> Union[str, dict]:
    """Resolve 'auto' arch from IDB metadata to a runner arch name.

    IDA reports AArch64 IDBs with procname "ARM" (64-bit) — the ARM family
    must be disambiguated by bitness FIRST, before any name-based fallback.
    """
    try:
        proc = str(ida_ida.inf_get_procname() or "")
        bits = int(ida_ida.inf_get_app_bitness())
    except Exception as e:
        return {"error": f"cannot read IDB arch: {e}"}
    low = proc.lower()
    if "arm" in low or "aarch64" in low:
        return "arm64" if bits == 64 else "arm"
    norm = normalize_arch(proc, bits) or ""
    table = {"arm64": "arm64", "arm": "arm", "x86_64": "x64", "x86": "x86"}
    if norm in table:
        return table[norm]
    return {"error": f"unsupported arch for emulation: {proc!r} ({bits}-bit)",
            "supported": sorted(table)}


def _resolve_ea(query: Union[int, str]) -> Union[int, dict]:
    parsed = parse_address(query)
    if parsed["ok"] and parsed["value"] is not None:
        return parsed["value"]
    if isinstance(query, str):
        try:
            ea = idc.get_name_ea_simple(query)
            if ea is not None and ea != idc.BADADDR:
                return int(ea)
        except Exception:
            pass
    return {"error": "cannot resolve address/name", "query": query}


def _build_image() -> Union[Dict[int, bytes], dict]:
    """Snapshot all IDB segments into {base: bytes} (total size capped)."""
    image: Dict[int, bytes] = {}
    total = 0
    for ea in idautils.Segments():
        s = ida_segment.getseg(ea)
        if not s:
            continue
        size = s.end_ea - s.start_ea
        if size <= 0:
            continue
        total += size
        if total > _IMAGE_CAP:
            return {"error": f"memory image exceeds {_IMAGE_CAP // (1024 * 1024)}MB cap",
                    "hint": "use emu_run with a trimmed IDB or manual writes instead"}
        data = ida_bytes.get_bytes(s.start_ea, size)
        if data:
            image[s.start_ea] = data
    if not image:
        return {"error": "no segments to emulate"}
    return image


def _parse_regs(regs: Optional[Dict[str, Union[int, str]]]) -> Union[Dict[str, int], dict, None]:
    if regs is None:
        return None
    out: Dict[str, int] = {}
    for name, val in regs.items():
        parsed = parse_address(val)
        if not parsed["ok"] or parsed["value"] is None:
            return {"error": f"invalid register value for {name!r}", "value": val}
        out[str(name).lower()] = parsed["value"]
    return out


def _parse_writes(writes: Optional[List[dict]]) -> Union[List, dict, None]:
    """Normalize [{"addr":..,"hex":"AA BB"|"AABB"} | {"addr":..,"bytes":[..]}] ->
    [(addr, bytes), ...]"""
    if writes is None:
        return None
    out: List = []
    for i, item in enumerate(writes):
        if not isinstance(item, dict):
            return {"error": f"writes[{i}] must be an object"}
        parsed = parse_address(item.get("addr"))
        if not parsed["ok"] or parsed["value"] is None:
            return {"error": f"writes[{i}]: invalid addr"}
        if "hex" in item:
            try:
                data = bytes.fromhex(str(item["hex"]).replace(" ", ""))
            except ValueError:
                return {"error": f"writes[{i}]: bad hex string"}
        elif "bytes" in item:
            try:
                data = bytes(int(b) & 0xFF for b in item["bytes"])
            except Exception:
                return {"error": f"writes[{i}]: bad bytes list"}
        elif "zeros" in item:
            try:
                n = int(item["zeros"])
                if n <= 0 or n > 64 * 1024 * 1024:
                    raise ValueError
                data = b"\x00" * n
            except Exception:
                return {"error": f"writes[{i}]: bad zeros count (1..64MB)"}
        else:
            return {"error": f"writes[{i}]: need 'hex', 'bytes' or 'zeros'"}
        out.append((parsed["value"], data))
    return out


def _free_base(image: Dict[int, bytes], want: int, size: int) -> int:
    """Find a free base address near `want` that does not overlap the image."""
    base = want
    for _ in range(64):
        clash = any(start < base + size and base < start + len(data)
                    for start, data in image.items())
        if not clash:
            return base
        base += 0x10000000
    return base  # runner will report a map conflict if still clashing


def _is_pe_idb() -> bool:
    try:
        base = min(idautils.Segments())
        head = ida_bytes.get_bytes(base, 0x1000) or b""
        return detect_format(head) == "pe"
    except Exception:
        return False


def _abi_auto(arch: str) -> str:
    table = {"arm64": "aapcs64", "arm": "aapcs32", "x86": "cdecl"}
    if arch == "x64":
        return "win64" if _is_pe_idb() else "sysv64"
    return table.get(arch, "aapcs64")


def _summarize_readbacks(
    result: Dict[str, Any],
    *,
    dump: bool,
    dump_prefix: str,
) -> List[Dict[str, Any]]:
    """Replace raw readback bytes with sha256+preview+magic scan (optional spill)."""
    summaries: List[Dict[str, Any]] = []
    for rb in result.pop("readbacks", []) or []:
        data = rb.get("data", b"")
        addr_s = rb.get("addr", "0x0")
        try:
            addr_i = int(addr_s, 16)
        except Exception:
            addr_i = 0
        entry: Dict[str, Any] = {
            "addr": addr_s,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "head_hex": data[:32].hex(" "),
            "entropy": round(blobscan.shannon_entropy(data), 3) if data else 0.0,
            "magics": blobscan.find_magics(data, addr_i)[:8],
        }
        if dump and data:
            fname = f"{dump_prefix}_{addr_i:X}_{len(data):X}.bin"
            path = os.path.join(tempfile.gettempdir(), "ida_mcp_out", fname)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(data)
            entry["file"] = path
        summaries.append(entry)
    return summaries


# ============================================================================
# Tools
# ============================================================================

@tool
@idaread
def emu_run(
    start: Annotated[Union[int, str], "Entry address or function name"],
    stop_at: Annotated[Union[int, str, List], "Stop address(es), comma-separated or list"] = "",
    regs: Annotated[Optional[Dict[str, Union[int, str]]], "Initial registers {name: value}"] = None,
    writes: Annotated[Optional[List[dict]], "Extra memory writes [{addr, hex|bytes}]"] = None,
    arch: Annotated[str, "auto|arm64|arm|x64|x86 (default: from IDB)"] = "auto",
    max_instructions: Annotated[int, "Instruction budget"] = 200000,
    watch_writes: Annotated[bool, "Track written memory and scan it for plaintext"] = True,
    dump: Annotated[bool, "Spill readback regions to files under %TEMP%/ida_mcp_out/"] = False,
) -> dict:
    """Emulate code with the IDB as memory image; write-watch catches plaintext algorithm-agnostically.

    Scope note: emulation starts with a clean CPU context, so code that depends
    on a live runtime frame (JIT/translation-cache blocks relying on rbp/rsp
    frame context or host-set registers) will not behave like in the real
    process — pass explicit regs for those, or analyze such blocks statically
    (scan_blocks / disasm_text / force_code_range).
    """
    err = _require_ida()
    if err:
        return err
    if not _emu_available():
        return {"error": "unicorn not installed in IDA python: pip install unicorn"}

    if arch == "auto":
        resolved = _arch_auto()
        if isinstance(resolved, dict):
            return resolved
        arch = resolved

    entry = _resolve_ea(start)
    if isinstance(entry, dict):
        return entry

    stops: List[int] = []
    for q in normalize_list_input(stop_at):
        parsed = parse_address(q)
        if not parsed["ok"] or parsed["value"] is None:
            return {"error": "invalid stop_at address", "value": q}
        stops.append(parsed["value"])

    reg_map = _parse_regs(regs)
    if isinstance(reg_map, dict) and "error" in reg_map:
        return reg_map
    write_list = _parse_writes(writes)
    if isinstance(write_list, dict) and "error" in write_list:
        return write_list

    image = _build_image()
    if isinstance(image, dict) and "error" in image:
        return image

    result = _core_run(
        image, arch, entry,
        stop_at=stops,
        regs=reg_map,
        writes=write_list or [],
        max_instructions=max(1, max_instructions),
        watch_writes=watch_writes,
        readback_dirty=watch_writes,
    )
    result["readback_summary"] = _summarize_readbacks(
        result, dump=dump, dump_prefix=f"emurun_{entry:X}")
    result["hint"] = ("dirty+magics shows WHERE plaintext landed (algorithm-agnostic); "
                      "feed the region to dump_region/extract_layer, or re-run with dump=true")
    return result


@tool
@idaread
def emu_call(
    func: Annotated[Union[int, str], "Function address or name (e.g. the decompressor)"],
    args: Annotated[Optional[List[Union[int, str]]], "Argument values; '@in'/'@out' = emulated buffers"] = None,
    abi: Annotated[str, "auto|aapcs64|aapcs32|sysv64|win64|cdecl"] = "auto",
    in_addr: Annotated[Optional[Union[int, str]], "IDB address to copy into the @in buffer"] = None,
    in_size: Annotated[int, "Bytes to copy from in_addr (required when in_addr is set)"] = 0,
    out_size: Annotated[int, "Expected output buffer size"] = 65536,
    out_name: Annotated[Optional[str], "Output file name (default emu_out_<entry>.bin)"] = None,
    regs: Annotated[Optional[Dict[str, Union[int, str]]], "Extra register overrides"] = None,
    writes: Annotated[Optional[List[dict]], "Extra memory writes [{addr, hex|bytes}] (props workspaces, structs)"] = None,
    max_instructions: Annotated[int, "Instruction budget"] = 2000000,
) -> dict:
    """Call a function under an ABI preset and dump its output buffer - the anti-hand-translation path.

    Scope note: works on self-contained routines (decompressors, decoders).
    JIT/translation-cache blocks that depend on a live rbp/rsp frame context
    are out of scope — the emulated call builds its own frame, so such code
    will compute wrong results or fault. Analyze those statically instead.
    """
    err = _require_ida()
    if err:
        return err
    if not _emu_available():
        return {"error": "unicorn not installed in IDA python: pip install unicorn"}

    resolved_arch = _arch_auto()
    if isinstance(resolved_arch, dict):
        return resolved_arch
    arch = resolved_arch

    if abi == "auto":
        abi = _abi_auto(arch)
    preset = _ABI_PRESETS.get(abi)
    if preset is None:
        return {"error": f"unknown abi {abi!r}", "supported": sorted(_ABI_PRESETS)}
    if preset.get("arch") != arch:
        return {"error": f"abi {abi!r} is for {preset.get('arch')}, IDB is {arch}"}

    entry = _resolve_ea(func)
    if isinstance(entry, dict):
        return entry

    image = _build_image()
    if isinstance(image, dict) and "error" in image:
        return image

    user_writes = _parse_writes(writes)
    if isinstance(user_writes, dict) and "error" in user_writes:
        return user_writes

    # ---- emulated in/out buffers ------------------------------------------
    in_len = 0
    io_writes: List = []
    if in_addr is not None:
        src = _resolve_ea(in_addr)
        if isinstance(src, dict):
            return src
        if in_size <= 0:
            return {"error": "in_size must be > 0 when in_addr is set"}
        raw = ida_bytes.get_bytes(src, in_size)
        if raw is None:
            return {"error": "failed to read input", "in_addr": hex_addr(src)}
        in_len = len(raw)
        io_writes.append((_free_base(image, _IN_BASE, in_len), raw))
    in_base = io_writes[0][0] if io_writes else _free_base(image, _IN_BASE, 0x1000)
    if in_addr is None:
        # map a scratch in page so '@in' never faults when no input was given
        io_writes.append((in_base, b"\x00"))
    out_base = _free_base(image, _OUT_BASE, max(out_size, 0x1000))
    # ensure the out buffer exists as mapped memory even if never written
    io_writes.append((out_base, b"\x00"))
    # user writes first, io buffers last (io wins on accidental overlap)
    writes_list: List = list(user_writes or []) + io_writes

    # ---- argument marshalling ----------------------------------------------
    call_regs: Dict[str, int] = {}
    stack_args: List[int] = []
    arg_regs: List[str] = list(preset.get("arg_regs", []))
    values: List[int] = []
    for a in (args or []):
        if isinstance(a, str) and a.strip().lower() == "@in":
            values.append(in_base)
        elif isinstance(a, str) and a.strip().lower() == "@out":
            values.append(out_base)
        else:
            parsed = parse_address(a)
            if not parsed["ok"] or parsed["value"] is None:
                return {"error": "invalid arg value", "arg": a}
            values.append(parsed["value"])
    for i, v in enumerate(values):
        if i < len(arg_regs):
            call_regs[arg_regs[i]] = v
        elif preset.get("stack_args"):
            stack_args.append(v)
        else:
            return {"error": f"too many args for abi {abi!r} (>{len(arg_regs)}); "
                             "pass the rest via regs"}

    overrides = _parse_regs(regs)
    if isinstance(overrides, dict) and "error" in overrides:
        return overrides
    if overrides:
        call_regs.update(overrides)

    result = _core_run(
        image, arch, entry,
        regs=call_regs,
        writes=writes_list,
        stack_args=stack_args,
        lr_sentinel=True,
        max_instructions=max(1, max_instructions),
        watch_writes=True,
        readback_dirty=True,
        reads=[(out_base, out_size)] + ([(in_base, in_len)] if in_len else []),
    )

    result["abi"] = abi
    result["buffers"] = {"in": hex_addr(in_base), "out": hex_addr(out_base),
                         "in_size": in_len, "out_size": out_size}
    result["readback_summary"] = _summarize_readbacks(
        result, dump=True, dump_prefix=out_name or f"emu_out_{entry:X}")
    result["hint"] = ("stop_reason=sentinel means a clean return; check "
                      "readback_summary[].magics for ELF/PE/DEX - that is your plaintext; "
                      "feed the region to extract_layer for the next IDA instance")
    return result
