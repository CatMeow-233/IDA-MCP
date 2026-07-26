"""SEMZ v1 DSL 输出层（SPEC §3，自包含文本）。

头部行：#SEMZ1 / #MN / #RG / #CT / #SQ / #JT / #ELIM；
标签行 `Ln:` 顶格；指令行缩进 2 空格；宏引用独占一行 `Pn`；
删除记录（level<max）以 `#- <ea> <编码指令> ; <reason>` 列在尾部。
"""
from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Tuple

from .model import Insn
from .normalize import branch_target_index, is_branch, is_call

# 操作数 token：0x 数 / 标识符 / 裸数字（[*N] 比例因子等）
_OP_TOKEN_RE = re.compile(r"0x[0-9A-F]+|[A-Za-z_.$][\w.$]*|\d+")
_NUM_RE = re.compile(r"0x[0-9A-F]+")


class Encoder:
    """把归一化 Insn 编码为 DSL 指令行。"""

    def __init__(
        self,
        mnem_map: Dict[str, str],
        reg_map: Dict[str, str],
        const_map: Dict[str, str],
        resolve_label: Optional[Callable[[int], Optional[str]]] = None,
        arch: str = "x64",
    ) -> None:
        self.mnem_map = mnem_map
        self.reg_map = reg_map
        self.const_map = const_map
        self.resolve_label = resolve_label or (lambda ea: None)
        self.arch = arch

    def encode(self, insn: Insn) -> str:
        code = self.mnem_map.get(insn.mnem, insn.mnem)
        ops_out: List[str] = []
        # 直接跳转/调用目标：内部地址 → 标签
        ti = branch_target_index(insn, self.arch)
        if (
            (is_branch(insn, self.arch) or is_call(insn, self.arch))
            and ti < len(insn.ops)
            and _NUM_RE.fullmatch(insn.ops[ti])
        ):
            label = self.resolve_label(int(insn.ops[ti], 16))
            ops_out = [self.encode_op(o) for o in insn.ops]
            if label is not None:
                ops_out[ti] = label
        else:
            ops_out = [self.encode_op(o) for o in insn.ops]
        if ops_out:
            return f"{code} {', '.join(ops_out)}"
        return code

    def encode_op(self, op: str) -> str:
        def repl(m: re.Match) -> str:
            tok = m.group(0)
            if m.start() > 0 and op[m.start() - 1] == ":":
                return tok  # `:d`/`:q` 尺寸标记，非符号/常量
            if tok in self.reg_map:
                return self.reg_map[tok]
            if _NUM_RE.fullmatch(tok):
                return self.const_map.get(tok, tok)
            if tok[0].isdigit():
                return tok  # 比例因子等裸数字保持内联
            # 标识符（API 名 / 标签名等）
            return self.const_map.get(tok, tok)

        return _OP_TOKEN_RE.sub(repl, op)


def _build_text(parts: dict, ratio_str: str) -> str:
    lines: List[str] = []
    lines.append(
        "#SEMZ1 fn={fn} arch={arch} level={level} orig={orig} out={out} "
        "elim={elim} ratio={ratio}%".format(ratio=ratio_str, **parts["head"])
    )
    if parts["mn"]:
        lines.append("#MN " + " ".join(f"{code}={mnem}" for code, mnem in parts["mn"]))
    if parts["rg"]:
        lines.append("#RG " + " ".join(f"{code}={canon}" for code, canon in parts["rg"]))
    if parts["ct"]:
        lines.append("#CT " + " ".join(f"{k}={tok}" for k, tok in parts["ct"]))
    for name, macro_lines in parts["sq"]:
        lines.append(f"#SQ {name}=" + ";".join(macro_lines))
    for line in parts.get("jt_lines") or []:
        lines.append(line)
    lines.append(f"#ELIM n={parts['head']['elim']}")
    for label, ea, blk_lines in parts["blocks"]:
        if ea is not None and parts["entry_label"] == label:
            lines.append(f"{label}:  ; entry 0x{ea:X}")
        else:
            lines.append(f"{label}:")
        lines.extend(f"  {ln}" for ln in blk_lines)
    lines.extend(parts["elim_lines"])
    return "\n".join(lines) + "\n"


def emit(blocks: List[Tuple[str, Optional[int], List[str]]], maps: dict, stats: dict, level: str) -> str:
    """装配最终 DSL 文本。

    Args:
        blocks: [(label, ea, [指令行...])]
        maps:   {"name","arch","mn","rg","ct","sq","jt","elim_lines","chars_in"}
        stats:  {"orig","out","elim"}；ratio 由本函数计算并回填
        level:  safe|full|max
    """
    parts = {
        "head": {
            "fn": str(maps.get("name") or "text").replace(" ", "_"),
            "arch": maps.get("arch") or "?",
            "level": level,
            "orig": stats["orig"],
            "out": stats["out"],
            "elim": stats["elim"],
        },
        "mn": maps.get("mn") or [],
        "rg": maps.get("rg") or [],
        "ct": maps.get("ct") or [],
        "sq": maps.get("sq") or [],
        "jt": maps.get("jt") or [],
        "blocks": blocks,
        "entry_label": blocks[0][0] if blocks else "",
        "elim_lines": maps.get("elim_lines") or [],
    }
    chars_in = max(int(maps.get("chars_in") or 1), 1)

    # ratio = chars_out/chars_in %，头部自引用，做不动点迭代直至位数稳定
    ratio_str = "0.0"
    text = _build_text(parts, ratio_str)
    for _ in range(4):
        new_ratio = f"{len(text) / chars_in * 100:.1f}"
        if new_ratio == ratio_str:
            break
        ratio_str = new_ratio
        text = _build_text(parts, ratio_str)

    stats["ratio"] = float(ratio_str)
    stats["chars_in"] = chars_in
    stats["chars_out"] = len(text)
    return text


# ============================================================================
# Ultra 级别（SPEC §5c，独立语法；不影响上方 safe/full/max 输出）
# ============================================================================

from .global_table import (  # noqa: E402
    ARM64_COND_CODES,
    ARM64_MNEMONIC_CODES,
    ARM64_SHIFT_SUFFIX,
    JCC_CODES,
    MEM_SIZE_SUFFIX,
    MNEMONIC_CODES,
    X86_MEM_SIZE_SUFFIX,
    encode_reg,
    encode_reg_arm64,
    encode_reg_x86,
    ultra_hex,
)
from .normalize import is_padding as _is_padding, is_reg_op as _is_reg_op  # noqa: E402

_ULTRA_JCC_RE = re.compile(
    r"j(z|nz|a|ae|b|be|g|ge|l|le|s|ns|o|no|p|np) (L\d+)"
)
_ULTRA_FUSED_RE = re.compile(r"g[a-z]+ L\d+: ")
_ULTRA_MACRO_REF_RE = re.compile(r"P\d+")


class UltraEncoder:
    """把归一化 Insn 编码为 ultra 指令行（全局固定表，无 #MN/#RG）。

    编码规则：
        - 助记符走全局固定表，未收录者原样小写拼写
        - 操作数以 `,` 连接（逗号后无空格）
        - 常量：进池的 → Kn；否则内联 ultra 十六进制（0ff 形）
        - 内存宽度标记 `:d` → 后缀 `4`，仅在无寄存器操作数可推断宽度时保留
        - 直接跳转/调用的内部目标 → 标签 Ln
        - nop/padding 返回 None（ultra 直接丢弃）
    """

    def __init__(
        self,
        const_map: Dict[str, str],
        resolve_label: Optional[Callable[[int], Optional[str]]] = None,
        arch: str = "x64",
    ) -> None:
        self.const_map = const_map
        self.resolve_label = resolve_label or (lambda ea: None)
        self.arch = arch

    def encode(self, insn: Insn) -> Optional[str]:
        if self.arch == "arm64":
            return self.encode_arm64(insn)
        if _is_padding(insn):
            return None
        code = MNEMONIC_CODES.get(insn.mnem, insn.mnem)
        # 内存宽度仅在无寄存器操作数时必需（如 mov [h-4]4,1 / k [h-14]4,0a）
        keep_width = not any(_is_reg_op(o) for o in insn.ops)
        ops_out: List[str] = []
        if (is_branch(insn) or is_call(insn)) and insn.ops and _NUM_RE.fullmatch(insn.ops[0]):
            label = self.resolve_label(int(insn.ops[0], 16))
            if label is not None:
                ops_out.append(label)
            else:
                ops_out.append(self.encode_op(insn.ops[0], keep_width))
            ops_out.extend(self.encode_op(o, keep_width) for o in insn.ops[1:])
        else:
            ops_out = [self.encode_op(o, keep_width) for o in insn.ops]
        if ops_out:
            return f"{code} {','.join(ops_out)}"
        return code

    # ------------------------------------------------------------------
    # ARM64 编码（SPEC §5d）
    # ------------------------------------------------------------------

    _A64_SHIFT_OP_RE = re.compile(r"^(lsl|lsr|asr|ror|uxtw|sxtw|uxtx|sxtx)(?: 0x([0-9A-F]+))?$")
    _A64_POST_IMM_RE = re.compile(r"-?0x[0-9A-F]+")

    def encode_arm64(self, insn: Insn) -> Optional[str]:
        """ARM64 ultra 编码（SPEC §5d 语法）。

        - 助记符走 ARM64 全局固定表（cbz/tbz/br/blr/svc 等按原样小写拼写）
        - 内存 `[S+40]` / 预索引 `[S-50]!` / 后索引 `p D,E,[S]+50`
        - 移位/扩展后缀挂在最后源操作数后（`:l3` / `:u` / `:u2`）
        - b.cond → `j<cc> Ln`（与 cmp/tst 的融合在 ultra_fuse_arm64 恒做）
        - 习语：`mov xd,#0` / `eor xd,xn,xn` → `z xd`；nop/hint 返回 None 丢弃
        """
        m = insn.mnem
        if m in ("nop", "hint"):
            return None
        ops = list(insn.ops)

        # 习语：清零
        if m == "mov" and len(ops) == 2 and ops[1] == "0x0":
            return f"z {self.encode_op_arm64(ops[0])}"
        if m == "eor" and len(ops) == 3 and ops[1] == ops[2]:
            return f"z {self.encode_op_arm64(ops[0])}"

        # 移位/扩展后缀折叠（tbz/tbnz 的第 2 操作数是位号立即数，非移位说明符）
        shift = ""
        if ops and m not in ("tbz", "tbnz"):
            sm = self._A64_SHIFT_OP_RE.fullmatch(ops[-1])
            if sm:
                amt = sm.group(2)
                shift = ":" + ARM64_SHIFT_SUFFIX[sm.group(1)]
                if amt:
                    shift += str(int(amt, 16))  # 位量按源值十进制书写（:l16）
                ops = ops[:-1]

        code = ARM64_MNEMONIC_CODES.get(m, m)

        # 独立 b.cond → `j<cc> Ln`
        if m.startswith("b."):
            cond = m[2:]
            tgt = self._label_or_op_arm64(ops[0]) if ops else ""
            return f"j{cond} {tgt}" if tgt else f"j{cond}"
        # b/bl 直接目标 → 标签
        if m in ("b", "bl"):
            tgt = self._label_or_op_arm64(ops[0]) if ops else ""
            return f"{code} {tgt}" if tgt else code
        # cbz/cbnz/tbz/tbnz 原生融合保持原样（目标 → 标签）
        if m in ("cbz", "cbnz") and len(ops) == 2:
            return f"{code} {self.encode_op_arm64(ops[0])},{self._label_or_op_arm64(ops[1])}"
        if m in ("tbz", "tbnz") and len(ops) == 3:
            return (
                f"{code} {self.encode_op_arm64(ops[0])},{self.encode_op_arm64(ops[1])},"
                f"{self._label_or_op_arm64(ops[2])}"
            )

        # 后索引写回：ldp x29,x30,[sp],#0x50 → p D,E,[S]+50
        post = ""
        if len(ops) >= 2 and ops[-2].endswith("]") and self._A64_POST_IMM_RE.fullmatch(ops[-1]):
            num = ops[-1]
            neg = num.startswith("-")
            body = num[1:] if neg else num
            lit = self.const_map.get(body) or ultra_hex(body)
            post = ("-" if neg else "+") + lit
            ops = ops[:-1]

        enc = [self.encode_op_arm64(o) for o in ops]
        if enc and shift:
            enc[-1] += shift
        if enc and post:
            enc[-1] += post
        if enc:
            return f"{code} {','.join(enc)}"
        return code

    def encode_op_arm64(self, op: str) -> str:
        def repl(m: re.Match) -> str:
            tok = m.group(0)
            rc = encode_reg_arm64(tok)
            if rc is not None:
                return rc
            if _NUM_RE.fullmatch(tok):
                return self.const_map.get(tok) or ultra_hex(tok)
            if tok[0].isdigit():
                return tok
            return self.const_map.get(tok, tok)  # API 名 / 标识符

        return _OP_TOKEN_RE.sub(repl, op)

    def _label_or_op_arm64(self, op: str) -> str:
        if _NUM_RE.fullmatch(op):
            label = self.resolve_label(int(op, 16))
            if label is not None:
                return label
        return self.encode_op_arm64(op)

    def encode_op(self, op: str, keep_width: bool = False) -> str:
        # x86（SPEC §5e）：裸写=eax 族；内存默认 dword 无后缀，非 dword 用 8/4/2/1
        x86 = self.arch == "x86"
        suffix = ""
        if "[" in op and ":" in op:
            op, _, size = op.rpartition(":")
            if keep_width:
                suffix = (X86_MEM_SIZE_SUFFIX if x86 else MEM_SIZE_SUFFIX).get(size, size)
        reg_encode = encode_reg_x86 if x86 else encode_reg

        def repl(m: re.Match) -> str:
            tok = m.group(0)
            if m.start() > 0 and op[m.start() - 1] == ":":
                return tok
            rc = reg_encode(tok)
            if rc is not None:
                return rc
            if _NUM_RE.fullmatch(tok):
                return self.const_map.get(tok) or ultra_hex(tok)
            if tok[0].isdigit():
                return tok  # 比例因子等裸数字保持内联
            return self.const_map.get(tok, tok)  # API 名 / 标识符

        return _OP_TOKEN_RE.sub(repl, op) + suffix


_ULTRA_ZERO_RE = re.compile(r"^x ([^,]+),\1$")
_ULTRA_TEST_RE = re.compile(r"^t ([^,]+),\1$")


def ultra_idioms(lines: List[str]) -> List[str]:
    """习语折叠：`x r,r` → `z r`（清零）；`t r,r` → `t r`（单操作数 test）。"""
    out: List[str] = []
    for ln in lines:
        m = _ULTRA_ZERO_RE.match(ln)
        if m:
            out.append(f"z {m.group(1)}")
            continue
        m = _ULTRA_TEST_RE.match(ln)
        if m:
            out.append(f"t {m.group(1)}")
            continue
        out.append(ln)
    return out


def ultra_merge_pushes(lines: List[str]) -> List[str]:
    """多压栈合并：连续的 `p X` 折叠为 `p X,Y`。"""
    out: List[str] = []
    for ln in lines:
        if ln.startswith("p ") and out and out[-1].startswith("p "):
            out[-1] = out[-1] + "," + ln[2:]
        else:
            out.append(ln)
    return out


def ultra_fuse(lines: List[str]) -> List[str]:
    """cmp/test + jcc 恒融合：`g<cc> Ln: k|t <ops>`（如 `gz L5:t a`）。"""
    out: List[str] = []
    i = 0
    while i < len(lines):
        if (
            i + 1 < len(lines)
            and (lines[i].startswith(("k ", "t ")))
            and _ULTRA_JCC_RE.fullmatch(lines[i + 1])
        ):
            m = _ULTRA_JCC_RE.fullmatch(lines[i + 1])
            out.append(f"g{m.group(1)} {m.group(2)}: {lines[i]}")
            i += 2
            continue
        out.append(lines[i])
        i += 1
    return out


def ultra_slot_count(line: str) -> int:
    """一行 ultra 正文对应的指令槽数：融合行=2，多压栈=操作数个数，其余=1。

    宏引用行（Pn）计 1（其展开数另计）。
    """
    if _ULTRA_MACRO_REF_RE.fullmatch(line):
        return 1
    if _ULTRA_FUSED_RE.match(line):
        return 2
    if line.startswith("p "):
        return line.count(",") + 1
    return 1


# ============================================================================
# ARM64 ultra 融合与槽计数（SPEC §5d）
# ============================================================================

_ULTRA_ARM64_BCOND_RE = re.compile(
    r"j(eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al) (L\d+)"
)


def ultra_fuse_arm64(lines: List[str]) -> List[str]:
    """cmp/tst + b.cond 恒融合：`g<cc> Ln: f|t <ops>`（如 `geq L2: f a,10`）。"""
    out: List[str] = []
    i = 0
    while i < len(lines):
        if i + 1 < len(lines) and lines[i].startswith(("f ", "t ")):
            m = _ULTRA_ARM64_BCOND_RE.fullmatch(lines[i + 1])
            if m:
                out.append(f"g{m.group(1)} {m.group(2)}: {lines[i]}")
                i += 2
                continue
        out.append(lines[i])
        i += 1
    return out


def ultra_slot_count_arm64(line: str) -> int:
    """ARM64 行槽数：g<cc> 融合行=2，宏引用=1，其余=1（无多压栈合并）。"""
    if _ULTRA_MACRO_REF_RE.fullmatch(line):
        return 1
    if _ULTRA_FUSED_RE.match(line):
        return 2
    return 1


def emit_ultra(
    blocks: List[Tuple[str, Optional[int], List[str]]],
    maps: dict,
    stats: dict,
) -> str:
    """装配 ultra 文本。

    头部：`#SZ1 fn=.. arch=.. at=0x.. o=.. u=.. e=.. r=..%`，随后恒出一行
    `#summary`（blocks/macros/consts/jt/frame 事实计数），按需追加
    `#K`（重复≥2 常量池）/ `#P`（重复≥2 序列宏）/ `#J`（跳转表）/ `#f=N`（标准帧消隐）。
    **不**输出 #MN/#RG（字典全局固定）。

    Args:
        blocks: [(label, ea, [ultra 指令行...])]
        maps:   {"name","arch","pool","macros","jt","frame","chars_in"}
        stats:  {"orig","elim"}；u/ratio/chars_* 由本函数计算并回填
    """
    slot_fn = ultra_slot_count_arm64 if maps.get("arch") == "arm64" else ultra_slot_count
    u = sum(slot_fn(ln) for _l, _e, lines in blocks for ln in lines)
    stats["out"] = u

    entry_ea = blocks[0][1] if blocks else None
    at = f"0x{entry_ea:X}" if entry_ea is not None else "0x0"

    def build(ratio_str: str) -> str:
        out_lines: List[str] = [
            "#SZ1 fn={fn} arch={arch} at={at} o={o} u={u} e={e} r={r}%".format(
                fn=str(maps.get("name") or "text").replace(" ", "_"),
                arch=maps.get("arch") or "?",
                at=at,
                o=stats["orig"],
                u=u,
                e=stats["elim"],
                r=ratio_str,
            )
        ]
        # 事实性摘要行：块/宏/常量计数、间接跳转数、帧大小（无语义描述）
        jt = maps.get("jt") or []
        summary = (
            f"#summary blocks={len(blocks)}"
            f" macros={len(maps.get('macros') or [])}"
            f" consts={len(maps.get('pool') or [])}"
            f" jt={len(jt)}{'(indirect)' if jt else ''}"
        )
        if maps.get("frame") is not None:
            summary += f" frame={int(maps['frame'])}"
        out_lines.append(summary)
        pool = maps.get("pool") or []
        if pool:
            out_lines.append("#K " + " ".join(f"{k}={tok}" for k, tok in pool))
        for name, macro_lines in maps.get("macros") or []:
            out_lines.append(f"#P {name}=" + ";".join(macro_lines))
        for line in maps.get("jt_lines") or []:
            out_lines.append(line)
        if maps.get("frame") is not None:
            frame = int(maps["frame"])
            fs = f"{frame:x}"
            out_lines.append("#f=" + ("0" + fs if fs and fs[0] in "abcdef" else fs))
        for label, _ea, blk_lines in blocks:
            out_lines.append(f"{label}:")
            out_lines.extend(blk_lines)
        return "\n".join(out_lines) + "\n"

    chars_in = max(int(maps.get("chars_in") or 1), 1)
    ratio_str = "0.0"
    text = build(ratio_str)
    for _ in range(4):
        new_ratio = f"{len(text) / chars_in * 100:.1f}"
        if new_ratio == ratio_str:
            break
        ratio_str = new_ratio
        text = build(ratio_str)

    stats["ratio"] = float(ratio_str)
    stats["chars_in"] = chars_in
    stats["chars_out"] = len(text)
    return text
