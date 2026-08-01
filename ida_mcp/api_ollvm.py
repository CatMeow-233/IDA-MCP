"""OLLVM API - obfuscation detection scoring and conservative opaque-predicate simplification.

Provides tools:
    - detect_ollvm      score a function for OLLVM obfuscation signals (cmov density,
                        opaque predicates, control-flow flattening)
    - ollvm_simplify    conservatively patch trivially-decidable opaque predicates
                        (dry_run by default)
"""
from __future__ import annotations

import re
from collections import namedtuple
from typing import Annotated, Optional, Union, List

from .rpc import tool
from .sync import idaread, idawrite, wait_for_auto_analysis
from .utils import parse_address, hex_addr
from .api_analysis import _resolve_function, _strip_tags

# IDA module imports
try:
    import idaapi  # type: ignore
    import ida_ida  # type: ignore
    import idautils  # type: ignore
    import ida_funcs  # type: ignore
    import ida_bytes  # type: ignore
    import ida_gdl  # type: ignore
except ImportError:
    idaapi = None
    ida_ida = None
    idautils = None
    ida_funcs = None
    ida_bytes = None
    ida_gdl = None

_MAX_EVIDENCE = 10

# ============================================================================
# Pure helpers (unit-testable without IDA)
# ============================================================================


def _score_metrics(metrics: dict) -> tuple:
    """把 detect_ollvm 收集的指标映射为 0-100 总分与 verdict。纯函数，便于单测。

    权重（满分 100）：
      - cmov 密度（30 分）：>=8% → 30，>=5% → 24，>=2% → 12，>=1% → 4，否则 0。
        正常代码 cmov 密度通常 <1%，OLLVM 混淆常见 >5%。
      - 不透明谓词命中数（40 分）：每命中 +8，封顶 40（即 >=5 处即满分）。
      - 控制流平坦化（30 分）：
          * 存在高扇入 dispatcher 块（fanin >= 5）→ +15
          * 基本块多（>=25）且 call 极少（<= max(2, blocks//10)）→ +10
          * 同一 state 变量 cmp imm 分发次数 >=8 → +5，>=5 → +3

    verdict：score >= 60 → "likely_ollvm"；>= 30 → "suspicious"；否则 "normal"。
    """
    density = float(metrics.get("cmov_density", 0.0))
    if density >= 0.08:
        cmov_pts = 30
    elif density >= 0.05:
        cmov_pts = 24
    elif density >= 0.02:
        cmov_pts = 12
    elif density >= 0.01:
        cmov_pts = 4
    else:
        cmov_pts = 0

    opaque_pts = min(40, int(metrics.get("opaque_pred_hits", 0)) * 8)

    flat_pts = 0
    if int(metrics.get("dispatcher_max_fanin", 0)) >= 5:
        flat_pts += 15
    blocks = int(metrics.get("blocks", 0))
    calls = int(metrics.get("calls", 0))
    if blocks >= 25 and calls <= max(2, blocks // 10):
        flat_pts += 10
    state_cmps = int(metrics.get("state_var_cmp_max", 0))
    if state_cmps >= 8:
        flat_pts += 5
    elif state_cmps >= 5:
        flat_pts += 3

    score = min(100, cmov_pts + opaque_pts + flat_pts)
    if score >= 60:
        verdict = "likely_ollvm"
    elif score >= 30:
        verdict = "suspicious"
    else:
        verdict = "normal"
    return score, verdict


# 轻量指令表示：字段与 capstone CsInsn 同名，_find_opaque_predicates 两者皆可消费。
LightInsn = namedtuple("LightInsn", ["address", "size", "bytes", "mnemonic", "op_str"])

_ZERO_SETTERS = ("xor", "sub")          # xor/sub reg, reg → reg = 0, ZF = 1
_JCC_TAKEN = ("jz", "je")               # ZF=1 时必跳
_JCC_NOT_TAKEN = ("jnz", "jne")         # ZF=1 时必不跳


def _same_reg_operands(op_str: str) -> Optional[str]:
    """'eax, eax' → 'eax'；操作数不是两个相同寄存器名 → None。"""
    parts = [p.strip() for p in (op_str or "").split(",")]
    if len(parts) == 2 and parts[0] == parts[1] and re.fullmatch(r"[a-zA-Z][a-zA-Z0-9]*", parts[0]):
        return parts[0]
    return None


def _find_opaque_predicates(insns) -> List[dict]:
    """在指令序列中识别可静态判定结果的简单不透明谓词。纯函数，便于单测。

    只做紧邻指令模式，不做数据流分析，宁可漏不可错：
      - xor/sub reg, reg（同寄存器）后紧跟 jz/je → 必跳；紧跟 jnz/jne → 必不跳
      - cmp reg, reg（同寄存器）后 jz/je → 必跳；jnz/jne → 必不跳
      - test reg, reg 后 jcc，且 test 的前一条是 xor/sub reg, reg 清零同一寄存器
        → jz/je 必跳；jnz/jne 必不跳

    insns 为 capstone CsInsn 列表或 LightInsn 列表（需有 address/size/bytes/
    mnemonic/op_str 属性）。返回 [{ea, kind, size, bytes, desc}]，ea 为 jcc 地址。
    """
    found = []
    n = len(insns)
    for i in range(n - 1):
        cur, nxt = insns[i], insns[i + 1]
        cur_mn = (cur.mnemonic or "").lower()
        nxt_mn = (nxt.mnemonic or "").lower()
        if nxt_mn not in _JCC_TAKEN + _JCC_NOT_TAKEN:
            continue

        kind = None
        desc = None
        reg = _same_reg_operands(cur.op_str)
        if reg and cur_mn in _ZERO_SETTERS + ("cmp",):
            # xor/sub/cmp reg,reg 直接紧邻 jcc（test 单独不可判定，见下）
            taken = nxt_mn in _JCC_TAKEN
            kind = "always_jump" if taken else "never_jump"
            desc = "%s %s, %s ; %s" % (cur_mn, reg, reg, nxt_mn)
        elif reg and cur_mn == "test" and i > 0:
            # test reg, reg 且前一条是清零同一寄存器的 xor/sub reg, reg
            prev = insns[i - 1]
            prev_mn = (prev.mnemonic or "").lower()
            if prev_mn in _ZERO_SETTERS and _same_reg_operands(prev.op_str) == reg:
                taken = nxt_mn in _JCC_TAKEN
                kind = "always_jump" if taken else "never_jump"
                desc = "%s %s, %s ; test ; %s" % (prev_mn, reg, reg, nxt_mn)

        if kind:
            found.append({
                "ea": int(nxt.address),
                "kind": kind,
                "size": int(nxt.size),
                "bytes": bytes(nxt.bytes),
                "desc": desc,
            })
    return found


# ============================================================================
# detect_ollvm
# ============================================================================

_JCC_MN_RE = re.compile(r"^j[a-z]+$")
_IMM_RE = re.compile(r"^(?:0[xX][0-9a-fA-F]+|\d+)[hH]?$")


def _collect_function_text(start_ea: int):
    """[(ea, mnemonic, op_str_text)]，op_str 已 strip tags。"""
    out = []
    for ea in idautils.FuncItems(start_ea):
        text = _strip_tags(idaapi.generate_disasm_line(ea, 0) or "")
        text = text.strip()
        if not text:
            continue
        parts = text.split(None, 1)
        mn = parts[0].lower()
        ops = parts[1] if len(parts) > 1 else ""
        out.append((ea, mn, ops))
    return out


def _detect_opaque_predicates_text(items):
    """基于反汇编文本的不透明谓词信号扫描（宽松，仅用于评分计数）。

    命中模式：
      1. cmp/xor/sub reg, reg（同寄存器）后 3 条内出现 jcc
      2. imul 后 3 条内出现 dec 或 and reg, 1，且随后 3 条内有 jcc
         （经典 x*(x-1)&1 恒偶/恒零谓词）
      3. mov reg, imm 置常量后 3 条内 cmp reg, imm 并接 jcc（常量比较恒真/恒假）
    """
    hits = []
    n = len(items)
    for i, (ea, mn, ops) in enumerate(items):
        tail = items[i + 1: i + 4]
        has_jcc = any(_JCC_MN_RE.match(m) and m != "jmp" for _, m, _ in tail)
        if not has_jcc:
            continue
        reg = _same_reg_operands(ops)
        if reg and mn in ("cmp", "xor", "sub"):
            hits.append(ea)
            continue
        if mn == "imul":
            for _, m2, o2 in tail:
                if m2 == "dec" or (m2 == "and" and re.search(r",\s*1\s*$", o2)):
                    hits.append(ea)
                    break
            continue
        if mn == "mov":
            parts = [p.strip() for p in ops.split(",")]
            if len(parts) == 2 and _IMM_RE.match(parts[1]):
                for _, m2, o2 in tail:
                    if m2 in ("cmp", "test") and o2.split(",")[0].strip() == parts[0]:
                        hits.append(ea)
                        break
    return hits


def _collect_cfg_metrics(func, items):
    """FlowChart 指标：块数、call 数、最大扇入、state 变量 cmp 分发。"""
    blocks = []
    calls = 0
    if ida_gdl is not None:
        try:
            fc = ida_gdl.FlowChart(func)
            blocks = list(fc)
        except Exception:
            blocks = []
    fanin = {}
    for b in blocks:
        for s in b.succs():
            fanin[s.id] = fanin.get(s.id, 0) + 1
    max_fanin = max(fanin.values()) if fanin else 0
    dispatcher_blocks = [b for b in blocks if fanin.get(b.id, 0) >= 5]

    # state 变量：cmp <同一操作数>, imm 的分发次数
    cmp_ops = {}
    cmp_evidence = {}
    for ea, mn, ops in items:
        if mn == "call":
            calls += 1
        if mn != "cmp":
            continue
        parts = [p.strip() for p in ops.split(",")]
        if len(parts) == 2 and _IMM_RE.match(parts[1]):
            key = parts[0]
            cmp_ops[key] = cmp_ops.get(key, 0) + 1
            cmp_evidence.setdefault(key, []).append(ea)
    state_var_cmp_max = max(cmp_ops.values()) if cmp_ops else 0
    state_ea = []
    if cmp_ops:
        top_key = max(cmp_ops, key=cmp_ops.get)
        state_ea = cmp_evidence[top_key]

    return {
        "blocks": len(blocks),
        "calls": calls,
        "dispatcher_max_fanin": max_fanin,
        "dispatcher_blocks": len(dispatcher_blocks),
        "state_var_cmp_max": state_var_cmp_max,
        "_dispatcher_ea": [int(b.start_ea) for b in dispatcher_blocks],
        "_state_ea": state_ea,
    }


@tool
@idaread
def detect_ollvm(
    query: Annotated[Union[int, str], "Function address or symbol name"],
) -> dict:
    """Score a function for OLLVM obfuscation (cmov density, opaque predicates, control-flow flattening).

    壳分析场景：OLLVM 混淆（控制流平坦化、不透明谓词、cmov 链）的量化检测。
    返回 0-100 总分与 verdict（likely_ollvm/suspicious/normal），并给出每项指标的
    数值与命中证据地址（各最多 10 条）。评分规则见 _score_metrics docstring。
    """
    if idaapi is None or idautils is None or ida_funcs is None:
        return {"error": "IDA modules unavailable"}
    wait_for_auto_analysis()

    resolved = _resolve_function(query)
    if "error" in resolved:
        return {"error": resolved["error"], "query": query}

    func = resolved["function"]
    try:
        items = _collect_function_text(resolved["start_ea"])
    except Exception as e:
        return {"error": "failed to collect instructions: %s" % e, "query": query}
    if not items:
        return {"error": "no instructions in function", "query": query}

    total = len(items)
    cmov_ea = [ea for ea, mn, _ in items if mn.startswith("cmov")]
    opaque_ea = _detect_opaque_predicates_text(items)

    cfg = _collect_cfg_metrics(func, items)
    dispatcher_ea = cfg.pop("_dispatcher_ea")
    state_ea = cfg.pop("_state_ea")

    metrics = {
        "instructions": total,
        "cmov_count": len(cmov_ea),
        "cmov_density": round(len(cmov_ea) / float(total), 4),
        "opaque_pred_hits": len(opaque_ea),
    }
    metrics.update(cfg)

    score, verdict = _score_metrics(metrics)

    return {
        "query": query,
        "function": resolved["name"],
        "start_ea": hex_addr(resolved["start_ea"]),
        "end_ea": hex_addr(resolved["end_ea"]),
        "score": score,
        "verdict": verdict,
        "metrics": metrics,
        "evidence": {
            "cmov": [hex_addr(ea) for ea in cmov_ea[:_MAX_EVIDENCE]],
            "opaque_predicates": [hex_addr(ea) for ea in opaque_ea[:_MAX_EVIDENCE]],
            "dispatcher": [hex_addr(ea) for ea in dispatcher_ea[:_MAX_EVIDENCE]],
            "state_var_cmp": [hex_addr(ea) for ea in state_ea[:_MAX_EVIDENCE]],
        },
    }


# ============================================================================
# ollvm_simplify
# ============================================================================


def _get_capstone_mode():
    """按 IDB 位宽选 CS_MODE_64/32；无法判定时默认 64。"""
    try:
        from capstone import CS_MODE_32, CS_MODE_64
    except ImportError:
        return None
    is64 = True
    if ida_ida is not None:
        try:
            is64 = bool(ida_ida.inf_is_64bit())
        except Exception:
            is64 = True
    return CS_MODE_64 if is64 else CS_MODE_32


@tool
@idawrite
def ollvm_simplify(
    ea: Annotated[Union[int, str], "Function address"],
    max_patches: Annotated[int, "Maximum number of patches to apply (safety cap)"] = 32,
    dry_run: Annotated[bool, "Report only, do not patch (default True)"] = True,
) -> dict:
    """Conservatively simplify trivially-decidable opaque predicates in a function (dry_run by default).

    只识别紧邻两条指令的恒跳/恒不跳模式（xor/sub/cmp reg,reg 后紧跟 jcc，
    或清零链后 test reg,reg + jcc），宁可漏不可错。
    dry_run=False 时：必跳 → jcc 短跳 patch 为 EB jmp（仅 2 字节短跳，
    0F 8x 长跳跳过并记录）；必不跳 → 整条 jcc NOP 填充。每个 patch 记录
    {ea, kind, old_bytes, new_bytes}，可用 IDA 撤销或按 old_bytes 恢复。
    """
    if ida_bytes is None or ida_funcs is None:
        return {"error": "IDA modules unavailable"}
    try:
        from capstone import Cs, CS_ARCH_X86
    except ImportError:
        return {"error": "capstone unavailable"}
    mode = _get_capstone_mode()
    if mode is None:
        return {"error": "capstone mode unavailable"}
    wait_for_auto_analysis()

    resolved = _resolve_function(ea)
    if "error" in resolved:
        return {"error": resolved["error"], "query": ea}
    start, end = resolved["start_ea"], resolved["end_ea"]

    code = ida_bytes.get_bytes(start, end - start)
    if not code:
        return {"error": "failed to read function bytes", "query": ea}

    md = Cs(CS_ARCH_X86, mode)
    md.detail = False
    insns = list(md.disasm(code, start))

    predicates = _find_opaque_predicates(insns)

    patched = []
    skipped = []
    for pred in predicates:
        if len(patched) >= max_patches:
            skipped.append({"ea": hex_addr(pred["ea"]), "reason": "max_patches reached",
                            "kind": pred["kind"]})
            continue

        jea = pred["ea"]
        old = pred["bytes"]
        new = None
        if pred["kind"] == "always_jump":
            if len(old) == 2 and old[0] in range(0x70, 0x80):
                # 短跳 jcc rel8 → jmp rel8（保留原偏移）
                new = bytes([0xEB, old[1]])
            else:
                skipped.append({"ea": hex_addr(jea), "reason": "near jcc (0F 8x) not patched, handle manually",
                                "kind": pred["kind"], "old_bytes": old.hex()})
                continue
        else:  # never_jump → NOP 填充整条 jcc
            new = b"\x90" * len(old)

        entry = {
            "ea": hex_addr(jea),
            "kind": pred["kind"],
            "desc": pred["desc"],
            "old_bytes": old.hex(),
            "new_bytes": new.hex(),
        }
        if not dry_run:
            try:
                ida_bytes.patch_bytes(jea, new)
                entry["applied"] = True
            except Exception as e:
                entry["applied"] = False
                entry["error"] = str(e)
        patched.append(entry)

    return {
        "query": ea,
        "function": resolved["name"],
        "start_ea": hex_addr(start),
        "dry_run": bool(dry_run),
        "candidates": len(predicates),
        "patched": patched,
        "skipped": skipped,
    }
