"""SEMZ 活性驱动消除（SPEC §1.4，保守启发式）。

反向寄存器+标志位活性分析。仅当指令同时满足以下条件才删除：
    - 无副作用（不写内存、非 call/jmp/push/pop/系统指令）
    - 其定义的全部寄存器均死
    - 不产生被后续消费（jcc/cmov/setcc/adc/sbb/lahf/pushf）的标志位
nop/padding 仅在 level=max 删除。level=safe 不做任何消除。

删除记录：[{ea, text, reason, insn}]（insn 供 dsl 输出编码形，非公开字段）。
"""
from __future__ import annotations

from typing import Dict, List, Optional, Set

from .model import Block
from .normalize import ARM64_GPR_FAMILIES, GPR_FAMILIES, access, is_padding

_TERMINAL_LIVE: Set[str] = set(GPR_FAMILIES)  # 无后继块（ret/间接 jmp）保守全部活跃
_TERMINAL_LIVE_ARM64: Set[str] = set(ARM64_GPR_FAMILIES)  # ARM64 同理（x0..x30+sp）


def _transfer(insns, live: Set[str], flag: bool, arch: str = "x64") -> tuple:
    """对块内指令做反向活性模拟（不删除），返回 (live_in, flag_in)。"""
    for ins in reversed(insns):
        acc = access(ins, arch)
        live = (live - acc["writes"]) | acc["reads"]
        flag = acc["flags_r"] or (flag and not acc["flags_w"])
    return live, flag


def eliminate_dead(
    blocks: List[Block],
    level: str = "full",
    succ: Optional[Dict[int, Set[int]]] = None,
    arch: str = "x64",
) -> tuple:
    """执行死代码消除。返回 (blocks, 删除记录 list)。"""
    if level == "safe" or not blocks:
        return blocks, []

    terminal = _TERMINAL_LIVE_ARM64 if arch == "arm64" else _TERMINAL_LIVE
    n = len(blocks)
    if succ is None:
        succ = {i: ({i + 1} if i + 1 < n else set()) for i in range(n)}

    # 块级活性不动点（先计算，供删除遍的块出口活跃集使用）
    live_in: List[Set[str]] = [set() for _ in range(n)]
    flag_in: List[bool] = [False] * n
    changed = True
    while changed:
        changed = False
        for i in range(n - 1, -1, -1):
            if succ.get(i):
                lo: Set[str] = set()
                fo = False
                for s in sorted(succ[i]):
                    lo |= live_in[s]
                    fo = fo or flag_in[s]
            else:
                lo = set(terminal)
                fo = True
            li, fi = _transfer(blocks[i].insns, set(lo), fo, arch)
            if li != live_in[i] or fi != flag_in[i]:
                live_in[i] = li
                flag_in[i] = fi
                changed = True

    # 删除遍（块内反向，被删指令不传播其读集）
    elim: List[dict] = []
    for i, blk in enumerate(blocks):
        if succ.get(i):
            live = set()
            flag = False
            for s in sorted(succ[i]):
                live |= live_in[s]
                flag = flag or flag_in[s]
        else:
            live = set(terminal)
            flag = True

        kept = []
        for ins in reversed(blk.insns):
            acc = access(ins, arch)
            reason = _deletable(ins, acc, live, flag, level, arch)
            if reason:
                elim.append({
                    "ea": ins.ea,
                    "text": ins.raw.strip(),
                    "reason": reason,
                    "insn": ins,
                })
                continue
            live = (live - acc["writes"]) | acc["reads"]
            flag = acc["flags_r"] or (flag and not acc["flags_w"])
            kept.append(ins)
        blk.insns = list(reversed(kept))

    elim.sort(key=lambda e: (e["ea"] is None, e["ea"] or 0, e["text"]))
    return blocks, elim


def _deletable(ins, acc: dict, live: Set[str], flag: bool, level: str, arch: str = "x64") -> Optional[str]:
    """按 SPEC §1.4 规则判定，返回删除原因或 None。"""
    if level == "max" and is_padding(ins, arch):
        return "padding"
    if acc["side"]:
        return None
    if not acc["writes"] and not acc["flags_w"]:
        return None  # 无定义可死（如 nop），full 级保留
    if acc["writes"] and not acc["writes"].isdisjoint(live):
        return None
    if acc["flags_w"] and flag:
        return None
    return "dead-after-overwrite" if acc["writes"] else "dead-flags"
