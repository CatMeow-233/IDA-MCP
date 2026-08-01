"""Auto-orchestration API - collapse the unpack loop into a single call.

Provides tools:
    - auto_unpack_layer  probe call-site args -> clone runtime workspaces ->
                         emulate the decompressor -> evidence-backed verdict

Design contract (SHELL_PLAYBOOK §8):
    the machine does the mechanical 80% (probe, clone, emulate, scan),
    and returns a VERDICT with an explicit `review_flags` checklist of every
    heuristic assumption it made. The human/LLM reviews the verdict and the
    flags - that is the 20%. Every claim carries machine-checkable evidence;
    ambiguous cases are labelled, never silently resolved.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
from typing import Annotated, Any, Dict, List, Optional, Tuple, Union

from .rpc import tool
from .sync import idaread
from .utils import parse_address, hex_addr, normalize_arch
from . import blobscan
from .api_emu import (
    _arch_auto, _resolve_ea, _build_image, _free_base, _parse_regs,
    _summarize_readbacks, _require_ida, _IN_BASE, _OUT_BASE,
)
from .api_shell import _iter_segments, _walk_code_immediates
from .emu.runner import run as _core_run
from .emu.runner import available as _emu_available
from .emu.runner import ABI_PRESETS as _ABI_PRESETS

try:
    import idc  # type: ignore
    import idautils  # type: ignore
    import ida_bytes  # type: ignore
    import ida_entry  # type: ignore
    import ida_funcs  # type: ignore
    import ida_ida  # type: ignore
except ImportError:
    idc = idautils = ida_bytes = ida_entry = ida_funcs = ida_ida = None  # type: ignore

_CLONE_CAP = 4 * 1024 * 1024     # max bytes cloned per pointer argument
_WS_CAP = 256 * 1024             # max bytes cloned from probe readbacks
_ZEROS_DEFAULT = 0x10000         # default size for faked/NULL pointer buffers


# ============================================================================
# Pure classification (unit-testable without IDA)
# ============================================================================

def classify_arg(
    value: int,
    segments: List[Tuple[int, int]],
    readback_regions: List[Tuple[int, int]],
) -> Dict[str, Any]:
    """Classify one ABI argument value.

    Returns {kind, value} where kind is one of:
      "image_ptr"    - points into a static image segment (clone from IDB)
      "runtime_ptr"  - points into probe-written memory (clone from readbacks)
      "null_ptr"     - 0 or tiny: loader fake/poisoned pointer -> zero buffer
      "wild_ptr"     - pointer-shaped but mapped nowhere -> zero buffer + flag
      "scalar"       - plain integer argument
    """
    if value < 0x1000:
        if value >= 0x100:
            return {"kind": "scalar", "value": value}
        return {"kind": "null_ptr" if value == 0 else "scalar", "value": value}
    for start, end in segments:
        if start <= value < end:
            return {"kind": "image_ptr", "value": value, "region": (start, end)}
    for start, end in readback_regions:
        if start <= value < end:
            return {"kind": "runtime_ptr", "value": value, "region": (start, end)}
    # pointer-shaped (aligned, 64-bit territory) but mapped nowhere
    if value >= 0x100000000 and value % 8 == 0:
        return {"kind": "wild_ptr", "value": value}
    # sub-4GB values outside any region are usually sizes/flags, but may be
    # 32-bit or rebased pointers - mark ambiguous so the caller flags it
    if value >= 0x10000:
        return {"kind": "scalar", "value": value, "ambiguous": True}
    return {"kind": "scalar", "value": value}


def guess_out_size(scalars: List[int], default: int = _ZEROS_DEFAULT) -> int:
    """Heuristic out-buffer size: largest plausible scalar, else default."""
    plausible = [s for s in scalars if 0x100 <= s <= 0x10000000]
    return max(plausible) if plausible else default


# ============================================================================
# Tool
# ============================================================================

@tool
@idaread
def auto_unpack_layer(
    func: Annotated[Optional[Union[int, str]], "Decompressor candidate; omit to auto-pick via immediates scan"] = None,
    entry: Annotated[Optional[Union[int, str]], "Probe start (default: IDB entry point)"] = None,
    probe_budget: Annotated[int, "Instruction budget for the call-site probe"] = 200000,
    max_instructions: Annotated[int, "Instruction budget for the decompressor run"] = 2000000,
    out_size: Annotated[int, "Override output buffer size (0 = heuristic)"] = 0,
) -> dict:
    """One-call unpack loop: probe args at the call site, clone workspaces, emulate, verdict."""
    err = _require_ida()
    if err:
        return err
    if not _emu_available():
        return {"error": "unicorn not installed in IDA python: pip install unicorn"}

    review: List[str] = []
    evidence: Dict[str, Any] = {}

    # ---- 0. arch / abi -----------------------------------------------------
    arch = _arch_auto()
    if isinstance(arch, dict):
        return arch
    abi = {"arm64": "aapcs64", "arm": "aapcs32", "x64": "sysv64"}.get(arch)
    if abi is None:
        return {"error": f"auto_unpack_layer does not support arch {arch} yet",
                "hint": "use emu_run/emu_call manually"}
    arg_regs: List[str] = list(_ABI_PRESETS[abi]["arg_regs"])
    ret_reg: str = _ABI_PRESETS[abi]["ret_reg"]

    # ---- 1. candidate function ---------------------------------------------
    if func is None:
        imms, _svc, _partial, _n = _walk_code_immediates(400000)
        best, best_score = None, 0
        for fea, rec in imms.items():
            score = 2 * sum(len(v) for v in rec["watch"].values()) + min(len(rec["suspicious"]), 5)
            if score > best_score:
                best, best_score = fea, score
        if best is None:
            return {"verdict": "failed", "reasons": ["no fingerprint candidate found"],
                    "hint": "run find_algo_signatures/scan_immediates and pass func explicitly"}
        func_ea = best
        review.append(f"func auto-picked by immediates scan: {hex_addr(func_ea)} (score {best_score})")
    else:
        func_ea = _resolve_ea(func)
        if isinstance(func_ea, dict):
            return func_ea
    fname = ida_funcs.get_func_name(func_ea) or hex_addr(func_ea)

    # ---- 2. probe start & call sites ----------------------------------------
    if entry is None:
        try:
            entry_ea = int(ida_ida.inf_get_start_ea())
        except Exception:
            entry_ea = None
        if entry_ea is None or entry_ea < 0:
            return {"verdict": "failed", "reasons": ["cannot resolve IDB entry point"],
                    "hint": "pass entry explicitly"}
        review.append(f"entry defaulted to IDB start {hex_addr(entry_ea)}")
    else:
        entry_ea = _resolve_ea(entry)
        if isinstance(entry_ea, dict):
            return entry_ea

    call_sites: List[int] = []
    try:
        for x in idautils.CodeRefsTo(func_ea, 1):
            if x not in call_sites:
                call_sites.append(x)
            if len(call_sites) >= 4:
                break
    except Exception:
        pass
    if not call_sites:
        return {"verdict": "failed", "reasons": [f"no code refs to {fname}"],
                "hint": "pass the real decompressor via func, or set a manual stop_at with emu_run"}
    evidence["call_sites"] = [hex_addr(c) for c in call_sites]

    # ---- 3. probe: run entry -> first call site -----------------------------
    image = _build_image()
    if isinstance(image, dict) and "error" in image:
        return image

    regs_out = list(dict.fromkeys(arg_regs + [ret_reg, "x30" if arch == "arm64" else arg_regs[0]]))
    probe = _core_run(
        image, arch, entry_ea,
        stop_at=call_sites,
        max_instructions=max(1, probe_budget),
        watch_writes=True,
        readback_dirty=True,
        regs_out=regs_out,
    )
    evidence["probe"] = {k: probe.get(k) for k in
                         ("ok", "stop_reason", "pc", "instructions", "svc_log", "fault")}
    if probe.get("stop_reason") != "stop_at":
        return {"verdict": "probe_failed", "function": fname,
                "reasons": [f"never reached a call site (stop={probe.get('stop_reason')})"],
                "evidence": evidence,
                "hint": "loader needs a real environment (svc ret0 may be too fake); "
                        "probe manually with emu_run and a different entry"}
    regs = probe.get("regs", {})

    def _reg_hex(name: str) -> Optional[int]:
        v = regs.get(name)
        if v is None:
            return None
        try:
            return int(str(v), 16)
        except Exception:
            return None

    # ---- 4. classify & clone args -------------------------------------------
    segs = [(s["start"], s["end"]) for s in _iter_segments()]
    rb_regions: List[Tuple[int, int]] = []
    for rb in probe.get("readbacks", []) or []:
        try:
            a = int(rb["addr"], 16)
            rb_regions.append((a, a + rb["size"]))
        except Exception:
            continue

    call_regs: Dict[str, int] = {}
    writes: List[Tuple[int, bytes]] = []
    reads: List[Tuple[int, int]] = []
    plan: List[Dict[str, Any]] = []
    next_buf = _OUT_BASE
    scalars: List[int] = []

    def _alloc(size: int) -> int:
        nonlocal next_buf
        base = next_buf
        next_buf += max(0x1000, (size + 0xFFF) & ~0xFFF) + 0x10000
        return base

    for i, rname in enumerate(arg_regs):
        val = _reg_hex(rname)
        if val is None:
            continue
        cls = classify_arg(val, segs, rb_regions)
        kind = cls["kind"]
        item: Dict[str, Any] = {"reg": rname, "value": hex_addr(val), "kind": kind}
        if kind == "scalar":
            scalars.append(val)
            call_regs[rname] = val
            if cls.get("ambiguous"):
                review.append(f"{rname}: {hex_addr(val)} treated as scalar but may be a "
                              "rebased/32-bit pointer - override manually if the run faults")
        elif kind == "image_ptr":
            start, end = cls["region"]
            size = min(end - val, _CLONE_CAP)
            data = ida_bytes.get_bytes(val, size) or b""
            buf = _alloc(max(len(data), 0x1000))
            writes.append((buf, data))
            call_regs[rname] = buf
            item["cloned"] = {"from": hex_addr(val), "size": len(data), "to": hex_addr(buf)}
            if end - val > _CLONE_CAP:
                review.append(f"{rname}: image region truncated at {_CLONE_CAP} bytes")
        elif kind == "runtime_ptr":
            start, _end = cls["region"]
            off = val - start
            data = b""
            for rb in probe.get("readbacks", []):
                if int(rb["addr"], 16) == start:
                    data = bytes(rb["data"][off:off + _WS_CAP])
                    break
            if not data:
                call_regs[rname] = val  # fall through as-is
                review.append(f"{rname}: runtime pointer {hex_addr(val)} not covered by "
                              "probe readbacks - passed through verbatim (LIKELY BROKEN)")
                item["kind"] = "runtime_ptr_unresolved"
            else:
                buf = _alloc(max(len(data), 0x1000))
                writes.append((buf, data))
                call_regs[rname] = buf
                item["cloned"] = {"from": hex_addr(val), "size": len(data), "to": hex_addr(buf)}
        else:  # null_ptr / wild_ptr
            buf = _alloc(_ZEROS_DEFAULT)
            writes.append((buf, b"\x00"))
            call_regs[rname] = buf
            item["allocated"] = {"to": hex_addr(buf), "size": _ZEROS_DEFAULT}
            review.append(f"{rname}: {kind} {hex_addr(val)} replaced by zero buffer "
                          f"{hex_addr(buf)} (loader value untrusted under emulation)")
        plan.append(item)

    heuristic_out = out_size if out_size > 0 else guess_out_size(scalars)
    review.append(f"out buffer size = {hex_addr(heuristic_out)} "
                  f"({'override' if out_size > 0 else 'heuristic: max scalar arg'})")

    # the most likely OUT buffer: the first allocated null/wild pointer, else @out
    out_candidates = [p for p in plan if "allocated" in p]
    if out_candidates:
        out_buf = int(str(out_candidates[0]["allocated"]["to"]), 16)
    else:
        out_buf = _alloc(heuristic_out)
        writes.append((out_buf, b"\x00"))
        review.append("no null/wild pointer arg - out buffer guessed as fresh allocation "
                      + hex_addr(out_buf))
    reads.append((out_buf, heuristic_out))
    evidence["arg_plan"] = plan

    # ---- 5. run the decompressor ---------------------------------------------
    result = _core_run(
        image, arch, func_ea,
        regs=call_regs,
        writes=writes,
        lr_sentinel=True,
        max_instructions=max(1, max_instructions),
        watch_writes=True,
        readback_dirty=True,
        reads=reads,
    )
    evidence["run"] = {k: result.get(k) for k in
                       ("ok", "stop_reason", "instructions", "svc_log", "fault", "warnings")}
    ret_hex = (result.get("regs") or {}).get(ret_reg)
    try:
        ret_val = int(str(ret_hex), 16)
    except Exception:
        ret_val = -1

    # ---- 6. verdict ------------------------------------------------------------
    summaries = _summarize_readbacks(result, dump=True,
                                     dump_prefix=f"auto_{func_ea:X}")
    out_summary = None
    # prefer the exact explicit-read entry (size == requested out size);
    # fall back to any summary covering the out buffer
    for s in summaries:
        if int(s["addr"], 16) == out_buf and s["size"] == heuristic_out:
            out_summary = s
            break
    if out_summary is None:
        for s in summaries:
            if int(s["addr"], 16) == out_buf:
                out_summary = s
                break
    evidence["readbacks"] = summaries

    reasons: List[str] = []
    if result.get("stop_reason") != "sentinel":
        reasons.append(f"no clean return (stop={result.get('stop_reason')})")
    if ret_val != 0:
        reasons.append(f"return value {ret_hex} != 0")
    if out_summary is None or not any(
            int(s["addr"], 16) == out_buf and s["size"] > 0 for s in summaries):
        reasons.append("out buffer never written / not read back")
    verdict = "success" if not reasons else "failed"
    if verdict == "success" and out_summary:
        if out_summary["magics"]:
            reasons.append(f"magic in output: "
                           + ",".join(m["type"] for m in out_summary["magics"]))
        review.append(f"output entropy {out_summary['entropy']} "
                      f"(input blobs are typically >7.5; a clear drop signals real plaintext)")

    return {
        "verdict": verdict,
        "function": fname,
        "ea": hex_addr(func_ea),
        "ret": ret_hex,
        "reasons": reasons,
        "review_flags": review,
        "evidence": evidence,
        "out_file": (out_summary or {}).get("file"),
        "hint": "review the flags: every heuristic assumption is listed; to override, "
                "call emu_call with explicit args/writes. Verify the dump adversarially "
                "(ida://shell/verifier_prompt) before trusting it downstream",
    }
