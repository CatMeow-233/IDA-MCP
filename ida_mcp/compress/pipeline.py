"""SEMZ 压缩管线（SPEC §1）：parse → normalize → cfg → liveness → 五层压缩 → dsl。"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Sequence, Tuple, Union

from . import cfg as _cfg
from . import dsl as _dsl
from . import layers as _layers
from . import liveness as _liveness
from . import parse as _parse
from .global_table import ultra_hex
from .model import Block, CompressError, Insn
from .normalize import (
    _REG_ALIAS,
    arm64_reg_family,
    branch_target_index,
    is_branch,
    is_call,
    normalize_insn,
    reg_family,
)

LEVELS = ("safe", "full", "max", "ultra")

_OP_TOKEN_RE = re.compile(r"0x[0-9A-F]+|[A-Za-z_.$][\w.$]*|\d+")
_NUM_RE = re.compile(r"0x[0-9A-F]+")
_JCC_LABEL_RE = re.compile(r"^(j[a-z0-9]+) (L\d+)$")
_FUSED_MAX_RE = re.compile(r"^cj[a-z0-9]+ L\d+: (.*)$")


def _coerce(insns: Union[List[dict], List[Insn]]) -> List[Insn]:
    """{ea,text,comment} dict 列表或 Insn 列表 → Insn 列表。"""
    out: List[Insn] = []
    for item in insns:
        if isinstance(item, Insn):
            out.append(item)
            continue
        if not isinstance(item, dict):
            continue
        ea = item.get("ea")
        if isinstance(ea, str):
            try:
                ea = int(ea, 0)
            except Exception:
                ea = None
        text = item.get("text") or ""
        insn = _parse.parse_line(str(text), ea=ea)
        if insn is not None:
            if item.get("comment") and not insn.comment:
                insn.comment = str(item["comment"])
            out.append(insn)
    return out


def _infer_arch(reg_names: Sequence[str]) -> str:
    x86 = False
    for name in reg_names:
        hit = _REG_ALIAS.get(name)
        if not hit:
            continue
        fam, width = hit
        if fam in ("rip",) or fam.startswith("r1") or fam in ("r8", "r9"):
            return "x64"
        if width == "q":
            return "x64"
        if width == "d":
            x86 = True
    return "x86" if x86 else "?"


def _collect_usage(
    blocks: List[Block],
    resolve_label,
    arch: str = "x64",
) -> Tuple[Dict[str, int], Dict[str, int], List[str]]:
    """统计助记符/寄存器/常量 token 用量（供 L1/L2/L3）。"""
    mnem_counts: Dict[str, int] = {}
    reg_counts: Dict[str, int] = {}
    const_seq: List[str] = []
    for blk in blocks:
        for ins in blk.insns:
            mnem_counts[ins.mnem] = mnem_counts.get(ins.mnem, 0) + 1
            ops = ins.ops
            # 内部直接跳转/调用目标 → 标签，不进常量池
            ti = branch_target_index(ins, arch)
            skip_idx = -1
            if (
                (is_branch(ins, arch) or is_call(ins, arch))
                and ti < len(ops)
                and _NUM_RE.fullmatch(ops[ti])
                and resolve_label(int(ops[ti], 16)) is not None
            ):
                skip_idx = ti
            for oi, op in enumerate(ops):
                if oi == skip_idx:
                    continue
                for m in _OP_TOKEN_RE.finditer(op):
                    tok = m.group(0)
                    if m.start() > 0 and op[m.start() - 1] == ":":
                        continue  # `:d`/`:q` 尺寸标记，非常量
                    if _NUM_RE.fullmatch(tok):
                        const_seq.append(tok)
                    elif tok[0].isdigit():
                        continue  # 比例因子等裸数字内联
                    elif _is_reg_token(tok, arch):
                        reg_counts[tok] = reg_counts.get(tok, 0) + 1
                    else:
                        const_seq.append(tok)  # API 名 / 字符串 / 标签名
    return mnem_counts, reg_counts, const_seq


def _is_reg_token(tok: str, arch: str) -> bool:
    if arch == "arm64":
        return arm64_reg_family(tok) is not None
    return reg_family(tok) is not None


def _fuse_cmp_jcc(block_lines: List[List[str]], mnem_map: Dict[str, str]) -> List[List[str]]:
    """level=max：cmp/test + jcc 融合为 `cj<cond> Ln: <cmp行>`。"""
    cmp_codes = {mnem_map.get("cmp"), mnem_map.get("test")} - {None}
    fused_blocks: List[List[str]] = []
    for lines in block_lines:
        out: List[str] = []
        i = 0
        while i < len(lines):
            if (
                i + 1 < len(lines)
                and cmp_codes
                and (lines[i] in cmp_codes or any(lines[i].startswith(c + " ") for c in cmp_codes))
            ):
                m = _JCC_LABEL_RE.match(lines[i + 1])
                if m and m.group(1) != "j":
                    out.append(f"cj{m.group(1)[1:]} {m.group(2)}: {lines[i]}")
                    i += 2
                    continue
            out.append(lines[i])
            i += 1
        fused_blocks.append(out)
    return fused_blocks


def _format_jt_lines(
    jt: List[dict],
    blocks: List[Block],
    jt_resolver,
    resolve_label,
    marker: str = "#J",
) -> List[str]:
    """格式化跳转表行：`<marker> L<所在块>: <目标列表|unresolved>`。

    目标由 jt_resolver 注入（IDA 侧为 xref 查询；纯文本侧为 None → unresolved）；
    能映射到块首地址的用标签，否则 ultra hex。
    """
    lines: List[str] = []
    for entry in jt:
        bi = entry.get("block")
        blk_label = (
            blocks[bi].label if isinstance(bi, int) and 0 <= bi < len(blocks) else "?"
        )
        targets = entry.get("targets")
        if targets is None and jt_resolver is not None and entry.get("ea") is not None:
            try:
                targets = jt_resolver(int(entry["ea"]))
            except Exception:
                targets = None
        names: List[str] = []
        for tea in targets or []:
            try:
                tea = int(tea)
            except (TypeError, ValueError):
                continue
            label = resolve_label(tea) if resolve_label is not None else None
            names.append(label if label else ultra_hex(f"0x{tea:X}"))
        if names:
            lines.append(f"{marker} {blk_label}: {','.join(names)}")
        else:
            lines.append(f"{marker} {blk_label}: unresolved")
    return lines


def _run(insns: List[Insn], level: str, name: str, arch: Optional[str], chars_in: int,
         jt_resolver=None) -> dict:
    if not insns:
        raise CompressError("no instructions")

    narch = _normalize_arch(arch)
    norm = [normalize_insn(i, narch) for i in insns]

    # cfg 重建 + L5 标签
    blocks, succ, jt = _cfg.build_blocks(norm, narch)
    _layers.assign_labels(blocks)

    # 活性消除（level>=full）
    blocks, elim = _liveness.eliminate_dead(blocks, level, succ=succ, arch=narch)

    # 直跳合并：标签引用改写指向最终标签（L0 除外）
    ea_to_label = {b.ea: b.label for b in blocks if b.ea is not None}
    tramp = _cfg.trampoline_map(blocks, ea_to_label, narch)

    def resolve_label(ea: int) -> Optional[str]:
        label = ea_to_label.get(ea)
        if label is None:
            return None
        seen = set()
        while label in tramp and label not in seen:
            seen.add(label)
            label = tramp[label]
        return label

    jt_lines = _format_jt_lines(jt, blocks, jt_resolver, resolve_label, marker="#JT")

    # L1/L2/L3
    mnem_counts, reg_counts, const_seq = _collect_usage(blocks, resolve_label, narch)
    mnem_map = _layers.build_mnemonic_map(mnem_counts)
    reg_map, reg_reverse = _layers.build_register_map(reg_counts, arch=narch)
    const_map, pool = _layers.build_const_pool(const_seq)

    encoder = _dsl.Encoder(mnem_map, reg_map, const_map, resolve_label, arch=narch)

    # 编码 → L4 序列挖掘
    block_lines: List[List[str]] = [
        [encoder.encode(ins) for ins in blk.insns] for blk in blocks
    ]
    block_lines, macros = _layers.mine_sequences(block_lines)

    # level=max：cmp/test+jcc 融合
    if level == "max":
        block_lines = _fuse_cmp_jcc(block_lines, mnem_map)

    # 头部字典（SPEC §3 "仅列实际用到的"）：以最终 emit 的行（融合后）为准。
    # 融合行 `cj<cond> Ln: <cmp行>` 只消耗 cmp/test 的码；jcc 恒等映射仅在
    # jcc 仍以独立行出现时才列入 #MN。
    mn_order = sorted(mnem_counts, key=lambda x: (-mnem_counts[x], x))
    code_of = {m: mnem_map[m] for m in mn_order if m in mnem_map}
    used_codes: set = set()
    for lines in block_lines:
        for ln in lines:
            if not ln or ln[0] == "P" and ln[1:].isdigit():
                continue  # 宏引用行
            fm = _FUSED_MAX_RE.match(ln)
            if fm:
                used_codes.add(fm.group(1).split(" ", 1)[0])
            else:
                used_codes.add(ln.split(" ", 1)[0])
    mn_header = [(code_of[m], m) for m in mn_order if code_of.get(m) in used_codes]
    rg_used: set = set()
    for blk in blocks:
        for ins in blk.insns:
            for op in ins.ops:
                for m in _OP_TOKEN_RE.finditer(op):
                    if m.group(0) in reg_map:
                        rg_used.add(reg_map[m.group(0)])
    rg_header = [(code, reg_reverse[code]) for code in sorted(rg_used) if code in reg_reverse]
    ct_header = pool

    # 删除记录尾部行（level<max 列明细；max 只留计数）
    elim_lines: List[str] = []
    if level != "max":
        for rec in elim:
            ea_s = f"0x{rec['ea']:X}" if rec["ea"] is not None else "?"
            enc = encoder.encode(rec["insn"])
            elim_lines.append(f"#- {ea_s} {enc} ; {rec['reason']}")

    stats = {
        "orig": len(norm),
        "out": sum(len(ls) for ls in block_lines),
        "elim": len(elim),
    }
    maps = {
        "name": name,
        "arch": arch or _infer_arch(list(reg_counts)),
        "mn": mn_header,
        "rg": rg_header,
        "ct": ct_header,
        "sq": macros,
        "jt": jt,
        "jt_lines": jt_lines,
        "elim_lines": elim_lines,
        "chars_in": chars_in,
    }
    emit_blocks = [(blk.label, blk.ea, block_lines[i]) for i, blk in enumerate(blocks)]
    text = _dsl.emit(emit_blocks, maps, stats, level)

    elim_public = [{"ea": r["ea"], "text": r["text"], "reason": r["reason"]} for r in elim]
    return {
        "text": text,
        "stats": stats,
        "elim": elim_public,
        "map": [(blk.label, blk.ea) for blk in blocks],
    }


# ============================================================================
# Ultra 级别（SPEC §5c，独立输出路径，不改变 safe/full/max 行为）
# ============================================================================

def _elide_frame(blocks: List[Block]) -> Optional[int]:
    """标准序言/尾声消隐（SPEC §5c）。命中返回帧字节数（可为 0），否则 None。

    序言（entry 块开头）：`push rbp; mov rbp,rsp; [sub rsp,N]`
    尾声（仅当序言已消隐）：`leave; ret` / `mov rsp,rbp; pop rbp; ret` /
    `add rsp,N; pop rbp; ret`。
    """
    if not blocks:
        return None
    first = blocks[0].insns
    if len(first) < 2:
        return None
    if not (
        first[0].mnem == "push" and first[0].ops == ["rbp"]
        and first[1].mnem == "mov" and first[1].ops == ["rbp", "rsp"]
    ):
        return None
    idx = 2
    frame = 0
    if (
        idx < len(first)
        and first[idx].mnem == "sub"
        and len(first[idx].ops) == 2
        and first[idx].ops[0] == "rsp"
        and _NUM_RE.fullmatch(first[idx].ops[1])
    ):
        frame = int(first[idx].ops[1], 16)
        idx += 1
    del first[:idx]

    def _is_ret(ins: Insn) -> bool:
        return ins.mnem == "retn" and not ins.ops

    for blk in blocks:
        ins = blk.insns
        if len(ins) >= 2 and ins[-2].mnem == "leave" and _is_ret(ins[-1]):
            del ins[-2:]
        elif (
            len(ins) >= 3
            and ins[-3].mnem == "mov" and ins[-3].ops == ["rsp", "rbp"]
            and ins[-2].mnem == "pop" and ins[-2].ops == ["rbp"]
            and _is_ret(ins[-1])
        ):
            del ins[-3:]
        elif (
            len(ins) >= 3
            and ins[-3].mnem == "add"
            and len(ins[-3].ops) == 2
            and ins[-3].ops[0] == "rsp"
            and _NUM_RE.fullmatch(ins[-3].ops[1])
            and ins[-2].mnem == "pop" and ins[-2].ops == ["rbp"]
            and _is_ret(ins[-1])
        ):
            del ins[-3:]
    return frame


def _elide_frame_x86(blocks: List[Block]) -> Optional[int]:
    """x86（32 位）标准帧消隐（SPEC §5e）。命中返回帧字节数（可为 0），否则 None。

    序言（entry 块开头）：`push ebp; mov ebp,esp; [sub esp,N]`
    尾声：`leave; ret[N]` / `mov esp,ebp; pop ebp; ret[N]` / `add esp,N; pop ebp; ret[N]`。
    `retn N`（stdcall 被调方清理）保留操作数（编码 `r N`），仅消隐帧维护指令。
    """
    if not blocks:
        return None
    first = blocks[0].insns
    if len(first) < 2:
        return None
    if not (
        first[0].mnem == "push" and first[0].ops == ["ebp"]
        and first[1].mnem == "mov" and first[1].ops == ["ebp", "esp"]
    ):
        return None
    idx = 2
    frame = 0
    if (
        idx < len(first)
        and first[idx].mnem == "sub"
        and len(first[idx].ops) == 2
        and first[idx].ops[0] == "esp"
        and _NUM_RE.fullmatch(first[idx].ops[1])
    ):
        frame = int(first[idx].ops[1], 16)
        idx += 1
    del first[:idx]

    for blk in blocks:
        ins = blk.insns
        if not ins or ins[-1].mnem != "retn":
            continue
        if len(ins) >= 2 and ins[-2].mnem == "leave":
            cut = 1  # leave
        elif (
            len(ins) >= 3
            and ins[-3].mnem == "mov" and ins[-3].ops == ["esp", "ebp"]
            and ins[-2].mnem == "pop" and ins[-2].ops == ["ebp"]
        ):
            cut = 2  # mov esp,ebp; pop ebp
        elif (
            len(ins) >= 3
            and ins[-3].mnem == "add"
            and len(ins[-3].ops) == 2
            and ins[-3].ops[0] == "esp"
            and _NUM_RE.fullmatch(ins[-3].ops[1])
            and ins[-2].mnem == "pop" and ins[-2].ops == ["ebp"]
        ):
            cut = 2  # add esp,N; pop ebp
        else:
            continue
        del ins[len(ins) - 1 - cut:len(ins) - 1]
        if not ins[-1].ops:
            del ins[-1]  # 裸 ret 随帧消隐；retn N 保留为 `r N`
    return frame


_A64_STP_PRE_RE = re.compile(r"\[sp-0x([0-9A-F]+)\]!")


def _elide_frame_arm64(blocks: List[Block]) -> Optional[int]:
    """ARM64 标准帧消隐（SPEC §5d）。命中返回总帧字节数，否则 None。

    序言（entry 块开头）：`stp x29,x30,[sp,#-N]!; [mov x29,sp]; [sub sp,sp,#M]`
    尾声：`[add sp,sp,#M]; ldp x29,x30,[sp],#N; ret`（含 add 变体）。
    总帧 = N + M。
    """
    if not blocks:
        return None
    first = blocks[0].insns
    if not first:
        return None
    i0 = first[0]
    if not (i0.mnem == "stp" and len(i0.ops) == 3
            and i0.ops[0] == "x29" and i0.ops[1] == "x30"):
        return None
    mm = _A64_STP_PRE_RE.fullmatch(i0.ops[2])
    if not mm:
        return None
    n_pre = int(mm.group(1), 16)
    idx = 1
    # mov x29,sp 可能已被 DCE 删除（x29 死），两种形态都接受
    if idx < len(first) and first[idx].mnem == "mov" and first[idx].ops == ["x29", "sp"]:
        idx += 1
    m_loc = 0
    if (idx < len(first) and first[idx].mnem == "sub" and len(first[idx].ops) == 3
            and first[idx].ops[0] == "sp" and first[idx].ops[1] == "sp"
            and _NUM_RE.fullmatch(first[idx].ops[2])):
        m_loc = int(first[idx].ops[2], 16)
        idx += 1
    del first[:idx]

    def _is_ret(ins: Insn) -> bool:
        return ins.mnem == "ret" and (not ins.ops or ins.ops == ["x30"])

    for blk in blocks:
        ins = blk.insns
        if len(ins) < 2 or not _is_ret(ins[-1]):
            continue
        li = ins[-2]
        if not (li.mnem == "ldp" and len(li.ops) == 4
                and li.ops[0] == "x29" and li.ops[1] == "x30" and li.ops[2] == "[sp]"
                and _NUM_RE.fullmatch(li.ops[3]) and int(li.ops[3], 16) == n_pre):
            continue
        cut = 2
        if len(ins) >= 3:
            ai = ins[-3]
            if (ai.mnem == "add" and len(ai.ops) == 3
                    and ai.ops[0] == "sp" and ai.ops[1] == "sp"
                    and _NUM_RE.fullmatch(ai.ops[2])):
                cut = 3  # add 变体
        del ins[-cut:]
    return n_pre + m_loc


def _run_ultra(insns: List[Insn], name: str, arch: Optional[str], chars_in: int,
               jt_resolver=None) -> dict:
    """ultra 管线：DCE 恒按 full 规则；输出走全局固定表，删除记录只留计数。"""
    if not insns:
        raise CompressError("no instructions")

    narch = _normalize_arch(arch)
    norm = [normalize_insn(i, narch) for i in insns]

    blocks, succ, jt = _cfg.build_blocks(norm, narch)
    _layers.assign_labels(blocks)

    # DCE：恒按修复后的 full 规则（带 CFG 后继）
    blocks, elim = _liveness.eliminate_dead(blocks, "full", succ=succ, arch=narch)

    # 直跳合并（同 full/max）
    ea_to_label = {b.ea: b.label for b in blocks if b.ea is not None}
    tramp = _cfg.trampoline_map(blocks, ea_to_label, narch)

    def resolve_label(ea: int) -> Optional[str]:
        label = ea_to_label.get(ea)
        if label is None:
            return None
        seen = set()
        while label in tramp and label not in seen:
            seen.add(label)
            label = tramp[label]
        return label

    jt_lines = _format_jt_lines(jt, blocks, jt_resolver, resolve_label, marker="#J")

    # 标准帧消隐（在 DCE 之后、编码之前）
    if narch == "arm64":
        frame = _elide_frame_arm64(blocks)
    elif narch == "x86":
        frame = _elide_frame_x86(blocks)
    else:
        frame = _elide_frame(blocks)

    # 常量池：重复 ≥2 且净正收益才进 #K，单次恒内联
    _mnem_counts, reg_counts, const_seq = _collect_usage(blocks, resolve_label, narch)
    const_map, pool = _layers.build_const_pool(const_seq, min_count=2)

    encoder = _dsl.UltraEncoder(const_map, resolve_label, arch=narch)
    block_lines: List[List[str]] = []
    for blk in blocks:
        lines: List[str] = []
        for ins in blk.insns:
            ln = encoder.encode(ins)
            if ln is not None:  # nop/padding 丢弃
                lines.append(ln)
        if narch == "arm64":
            lines = _dsl.ultra_fuse_arm64(lines)  # 习语已在编码器内折叠
        else:
            lines = _dsl.ultra_merge_pushes(_dsl.ultra_idioms(lines))
            lines = _dsl.ultra_fuse(lines)
        block_lines.append(lines)

    # 序列宏：重复 ≥2 才进 #P
    block_lines, macros = _layers.mine_sequences(block_lines)

    stats = {"orig": len(norm), "elim": len(elim)}
    maps = {
        "name": name,
        "arch": arch or _infer_arch(list(reg_counts)),
        "pool": pool,
        "macros": macros,
        "jt": jt,
        "jt_lines": jt_lines,
        "frame": frame,
        "chars_in": chars_in,
    }
    emit_blocks = [(blk.label, blk.ea, block_lines[i]) for i, blk in enumerate(blocks)]
    text = _dsl.emit_ultra(emit_blocks, maps, stats)
    return {
        "text": text,
        "stats": stats,
        "elim": [],  # 删除记录丢弃，仅 e= 计数
        "map": [(blk.label, blk.ea) for blk in blocks],
    }


def _normalize_arch(arch: Optional[str]) -> str:
    """管线内部架构：arm64 / x86 原样保留，其余（None/"x64"/显示值）走 x64 路径。

    x86 与 x64 同 ISA：normalize 的访问表/活性/CFG 逻辑全部复用 x64 路径
    （各模块以 `arch == "arm64"` 分派），仅归一化段前缀、寄存器编码与
    帧消隐按 "x86" 区分。
    """
    if arch in ("arm64", "x86"):
        return arch
    return "x64"


def _resolve_arch(parsed: List[Insn], arch: Optional[str]) -> Optional[str]:
    """arch 参数归一："auto"/None/"?" → 启发式探测（"arm64"/"x86"/None，
    None 走 x64 路径并沿用 _infer_arch 显示）；显式值原样透传。"""
    if arch in (None, "", "auto", "?"):
        return _parse.detect_arch(parsed)
    if arch == "arm64":
        return "arm64"
    return arch  # "x64"/"x86" 等：x64 路径，显示值透传


def compress_insns(
    insns: Union[List[dict], List[Insn]],
    level: str = "ultra",
    name: str = "text",
    arch: str = "auto",
    jt_resolver=None,
) -> dict:
    """压缩 {ea,text,comment} 指令列表。arch="auto"|"x86"|"x64"|"arm64"。返回 {text, stats, elim, map}。

    map 为 [(label, ea), ...]：Ln 标签 → 块首地址（DCE 后、地址序）。
    jt_resolver：可选 callable(ea:int)->list[int]|None，注入跳转表目标（IDA 侧 xref）。
    """
    if level not in LEVELS:
        raise CompressError(f"invalid level (must be one of {LEVELS})")
    parsed = _coerce(insns)
    eff_arch = _resolve_arch(parsed, arch)
    chars_in = len("\n".join(i.raw for i in parsed)) + (1 if parsed else 0)
    if level == "ultra":
        return _run_ultra(parsed, name, eff_arch, chars_in, jt_resolver=jt_resolver)
    return _run(parsed, level, name, eff_arch, chars_in, jt_resolver=jt_resolver)


def compress_text(text: str, level: str = "ultra", name: str = "text", arch: str = "auto") -> dict:
    """压缩汇编/Trace 文本（内部 parse → 同管线）。arch="auto"|"x86"|"x64"|"arm64"。返回 {text, stats, elim, map}。"""
    if level not in LEVELS:
        raise CompressError(f"invalid level (must be one of {LEVELS})")
    if not isinstance(text, str) or not text.strip():
        raise CompressError("empty text")
    parsed = _parse.parse_text(text)
    eff_arch = _resolve_arch(parsed, arch)
    if level == "ultra":
        return _run_ultra(parsed, name, eff_arch, len(text))
    return _run(parsed, level, name, eff_arch, len(text))
