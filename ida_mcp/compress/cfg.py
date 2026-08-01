"""SEMZ 控制流重建（SPEC §1.5）。

leader 判定：首指令、跳转目标、**任何**跳转（条件/无条件）与 ret 的下一条
（该指令本身可能不可达，单独成块即可；无条件跳转/ret 无 fall-through 后继边）；
call 不分块。
间接跳转 `jmp [reg*8+K]` 记入 jt 列表（纯文本侧 targets=None → `#JT unresolved`）。
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from .model import Block, Insn
from .normalize import branch_target_index, is_branch, is_call

_RET_MNEMS = {"retn", "retf", "iret", "iretd", "iretq"}
_ARM64_RET_MNEMS = {"ret", "retaa", "retab"}
_ARM64_UNCOND = {"b", "br"}          # 无条件（无 fall-through 后继）
_ARM64_CBR = {"cbz", "cbnz", "tbz", "tbnz"}
_ARM64_INDIRECT = {"br", "blr"}      # 间接（#J unresolved）
_NUM_RE = re.compile(r"0x[0-9A-F]+")


def _ret_mnems(arch: str) -> Set[str]:
    return _ARM64_RET_MNEMS if arch == "arm64" else _RET_MNEMS


def _direct_target_idx(insn: Insn, ea_index: Dict[int, int], arch: str = "x64") -> Optional[int]:
    """直接跳转/调用的目标指令下标（目标在范围内），否则 None。"""
    ti = branch_target_index(insn, arch)
    if ti >= len(insn.ops):
        return None
    if not _NUM_RE.fullmatch(insn.ops[ti]):
        return None
    return ea_index.get(int(insn.ops[ti], 16))


def build_blocks(
    insns: List[Insn],
    arch: str = "x64",
) -> Tuple[List[Block], Dict[int, Set[int]], List[dict]]:
    """构建基本块。

    Returns:
        blocks: 基本块列表（label 尚未分配，由 layers.assign_labels 完成）
        succ:   块下标 → 后继块下标集合
        jt:     间接跳转记录 [{"ea", "block", "targets": None|list[int]}]
    """
    n = len(insns)
    if n == 0:
        return [], {}, []

    ea_index: Dict[int, int] = {}
    for i, ins in enumerate(insns):
        if ins.ea is not None and ins.ea not in ea_index:
            ea_index[ins.ea] = i

    leaders: Set[int] = {0}
    rets = _ret_mnems(arch)
    for i, ins in enumerate(insns):
        if is_branch(ins, arch):
            t = _direct_target_idx(ins, ea_index, arch)
            if t is not None:
                leaders.add(t)
            if i + 1 < n:
                # 任何跳转（条件/无条件）的下一条都是 leader。
                # 无条件 jmp 之后的指令可能不可达，单独成块可避免 liveness
                # 块内线性扫描把它误当作前序定义的覆盖证据。
                leaders.add(i + 1)
        elif ins.mnem in rets and i + 1 < n:
            leaders.add(i + 1)  # ret 之后的指令同样单独成块（可能不可达）

    starts = sorted(leaders)
    blocks: List[Block] = []
    block_of_insn: Dict[int, int] = {}
    for bi, s in enumerate(starts):
        e = starts[bi + 1] if bi + 1 < len(starts) else n
        blk = Block(label="", ea=insns[s].ea, insns=list(insns[s:e]))
        blocks.append(blk)
        for idx in range(s, e):
            block_of_insn[idx] = bi

    succ: Dict[int, Set[int]] = {}
    jt: List[dict] = []
    for bi, blk in enumerate(blocks):
        last = blk.insns[-1]
        targets: Set[int] = set()
        if arch == "arm64":
            m = last.mnem
            if m in _ARM64_UNCOND:
                # b/br：无条件，无 fall-through 后继
                t = _direct_target_idx(last, ea_index, arch)
                if t is not None:
                    targets.add(block_of_insn[t])
                elif m in _ARM64_INDIRECT:
                    jt.append({"ea": last.ea, "block": bi, "targets": None})
            elif is_branch(last, arch):
                # b.cond/cbz/cbnz/tbz/tbnz：条件，有 fall-through
                t = _direct_target_idx(last, ea_index, arch)
                if t is not None:
                    targets.add(block_of_insn[t])
                if bi + 1 < len(blocks):
                    targets.add(bi + 1)
            elif m in rets:
                pass  # ret 终止
            else:
                if m in _ARM64_INDIRECT:  # blr 作为块末（call 不分块，但属间接）
                    jt.append({"ea": last.ea, "block": bi, "targets": None})
                if bi + 1 < len(blocks):
                    targets.add(bi + 1)
        elif last.mnem == "jmp":
            t = _direct_target_idx(last, ea_index, arch)
            if t is not None:
                targets.add(block_of_insn[t])
            elif not last.ops or not _NUM_RE.fullmatch(last.ops[0]):
                # 间接跳转：记录跳转表项
                jt.append({"ea": last.ea, "block": bi, "targets": None})
        elif is_branch(last, arch):
            t = _direct_target_idx(last, ea_index, arch)
            if t is not None:
                targets.add(block_of_insn[t])
            if bi + 1 < len(blocks):
                targets.add(bi + 1)  # fall-through
        elif last.mnem in rets:
            pass
        else:
            if bi + 1 < len(blocks):
                targets.add(bi + 1)
        succ[bi] = targets

    # 间接跳转也可能出现在块中部（非 last），一并记录
    for bi, blk in enumerate(blocks):
        for ins in blk.insns[:-1]:
            if arch == "arm64":
                if ins.mnem in _ARM64_INDIRECT:
                    jt.append({"ea": ins.ea, "block": bi, "targets": None})
            elif ins.mnem == "jmp" and ins.ops and not _NUM_RE.fullmatch(ins.ops[0]):
                jt.append({"ea": ins.ea, "block": bi, "targets": None})
    jt.sort(key=lambda e: (e["ea"] is None, e["ea"] or 0))

    return blocks, succ, jt


def trampoline_map(blocks: List[Block], ea_to_label: Dict[int, str], arch: str = "x64") -> Dict[str, str]:
    """直跳合并（SPEC §1.5）：块体仅含一条无条件直接 jmp/b 的块（L0 除外），
    返回 label → 最终 label 的映射（链式解析，带环保护）。"""
    uncond = "b" if arch == "arm64" else "jmp"
    raw: Dict[str, str] = {}
    for blk in blocks[1:]:
        if len(blk.insns) == 1 and blk.insns[0].mnem == uncond:
            ins = blk.insns[0]
            if ins.ops and _NUM_RE.fullmatch(ins.ops[0]):
                tgt = ea_to_label.get(int(ins.ops[0], 16))
                if tgt and tgt != blk.label:
                    raw[blk.label] = tgt

    final: Dict[str, str] = {}
    for label in raw:
        seen = {label}
        cur = label
        while cur in raw and raw[cur] not in seen:
            seen.add(raw[cur])
            cur = raw[cur]
        final[label] = cur
    return final
