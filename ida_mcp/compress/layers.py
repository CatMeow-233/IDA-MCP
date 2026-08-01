"""SEMZ 五层压缩（SPEC §1.3）。

L1 助记符字典   build_mnemonic_map
L2 寄存器字典   build_register_map
L3 常量池       build_const_pool
L4 序列字典     mine_sequences（3–8 长度、count>=2 的 n-gram，按节省贪心非重叠替换）
L5 地址标签化   assign_labels（按地址序，entry=L0）
"""
from __future__ import annotations

from typing import Dict, List, Sequence, Tuple

from .model import Block
from .normalize import JCC, arm64_reg_family, reg_family, reg_width, _REG_CANON

# ============================================================================
# L1 助记符字典
# ============================================================================

BUILTIN_MNEMONIC: Dict[str, str] = {
    "mov": "m", "push": "p", "pop": "q", "call": "c", "jmp": "j",
    "lea": "l", "add": "a", "sub": "s", "xor": "x", "cmp": "cp",
    "test": "t", "retn": "r",
}

_LOOP_MNEMS = {"loop", "loope", "loopne", "loopz", "loopnz"}


def build_mnemonic_map(mnem_counts: Dict[str, int]) -> Dict[str, str]:
    """助记符 → 短码。内置表优先；jcc/loop 恒等映射；其余按 (频率降序, 名称升序) 分配 m0,m1…"""
    code_map: Dict[str, str] = {}
    used_codes = set(BUILTIN_MNEMONIC.values())
    ordered = sorted(mnem_counts, key=lambda m: (-mnem_counts[m], m))
    fallback = 0
    for m in ordered:
        if m in BUILTIN_MNEMONIC:
            code_map[m] = BUILTIN_MNEMONIC[m]
        elif m in JCC or m in _LOOP_MNEMS:
            code_map[m] = m  # 恒等（#MN 中列出 jz=jz 等）
        else:
            while f"m{fallback}" in used_codes:
                fallback += 1
            code_map[m] = f"m{fallback}"
            used_codes.add(f"m{fallback}")
            fallback += 1
    return code_map


# ============================================================================
# L2 寄存器字典
# ============================================================================

# 族 → 短码。SPEC 内置 rax→a … r8..r15→8..f；
# 为避免与 rax..rdx 的 a..d 冲突，r10..r15 使用大写 A..F（残余歧义：r11=B 与 rbp=B
# 仅在同函数同时使用 r11 与 rbp 时冲突，属可接受的激进取舍）。
FAMILY_CODE: Dict[str, str] = {
    "rax": "a", "rbx": "b", "rcx": "c", "rdx": "d",
    "rsi": "si", "rdi": "di", "rsp": "S", "rbp": "B",
    "r8": "8", "r9": "9", "r10": "A", "r11": "B",
    "r12": "C", "r13": "D", "r14": "E", "r15": "F",
    "rip": "R",
}


# ARM64 族 → 短码（x0..x25→a..z, x26..x30→A..E, sp→S, xzr→Z, pc→P；w 视图加 !d）
_ARM64_FAMILY_CODE: Dict[str, str] = {f"x{i}": chr(ord("a") + i) for i in range(26)}
_ARM64_FAMILY_CODE.update({f"x{i}": chr(ord("A") + i - 26) for i in range(26, 31)})
_ARM64_FAMILY_CODE.update({"sp": "S", "xzr": "Z", "pc": "P"})


def build_register_map(
    reg_counts: Dict[str, int],
    arch: str = "x64",
) -> Tuple[Dict[str, str], Dict[str, str]]:
    """寄存器名 → 短码；子寄存器为族码+宽度后缀（al→a!b, ax→a!w, eax→a!d）。

    Returns:
        reg_map: 归一化寄存器名 → 短码
        reverse: 短码 → 代表名（#RG 头用，仅实际用到的）
    """
    reg_map: Dict[str, str] = {}
    reverse: Dict[str, str] = {}
    ordered = sorted(reg_counts, key=lambda r: (-reg_counts[r], r))
    for name in ordered:
        if arch == "arm64":
            fam = arm64_reg_family(name)
            if fam in _ARM64_FAMILY_CODE:
                base = _ARM64_FAMILY_CODE[fam]
                width = "d" if name.lower().startswith("w") and name.lower() not in ("wsp", "wzr") else "q"
                code = base if width == "q" else f"{base}!{width}"
                canon = name
            else:
                code = name  # SIMD/系统寄存器等 best-effort 透传
                canon = name
        else:
            fam = reg_family(name)
            width = reg_width(name)
            if fam in FAMILY_CODE:
                base = FAMILY_CODE[fam]
                code = base if width == "q" else f"{base}!{width or 'q'}"
                canon = _REG_CANON.get((fam, width or "q"), name)
            else:
                code = name  # xmm/st/段寄存器等 best-effort 透传
                canon = name
        reg_map[name] = code
        reverse.setdefault(code, canon)
    return reg_map, reverse


# ============================================================================
# L3 常量池
# ============================================================================

def build_const_pool(
    token_seq: Sequence[str],
    min_count: int = 1,
    min_inline_len: int = 5,
) -> Tuple[Dict[str, str], List[Tuple[str, str]]]:
    """立即数/位移/字符串/API 名 → K0..Kn。

    规则（SPEC §1.3 L3）：内联拼写 <min_inline_len 字符的小常量恒内联不进池
    （如 0x60/0x1F 这类掩码，池化不省字符还增加心智开销）；
    其余按实际字符收益决策：仅当 `count*(内联长-len(Kn))` 大于
    头部定义开销 `len("Kn=")+len+1` 时才进池（净正收益）。
    ultra（SPEC §5c）以 min_count=2 调用：重复 ≥2 才允许进池，单次恒内联。
    池内顺序按首次出现（确定性）。

    Returns:
        const_map: token → Kn（仅进池的）
        pool:      [(Kn, token)] 按分配序
    """
    counts: Dict[str, int] = {}
    order: List[str] = []
    for tok in token_seq:
        if tok not in counts:
            counts[tok] = 0
            order.append(tok)
        counts[tok] += 1
    const_map: Dict[str, str] = {}
    pool: List[Tuple[str, str]] = []
    for tok in order:
        name = f"K{len(pool)}"
        # 内联拼写长度：ultra 十六进制省略 0x 前缀（0x60 → "60"）；
        # 门槛用内联长（挡住 0x60/0x1F 等小常量），收益按 tok 全长计
        # （0x405030 这类绝对地址池化有实际字符+语义分组收益，见测试）
        inline_len = len(tok) - 2 if tok.startswith(("0x", "0X")) else len(tok)
        saving = counts[tok] * max(0, len(tok) - len(name))
        cost = len(name) + 1 + len(tok) + 1  # "Kn=tok "
        if (
            counts[tok] >= min_count
            and inline_len >= min_inline_len
            and saving > cost
        ):
            const_map[tok] = name
            pool.append((name, tok))
    return const_map, pool


# ============================================================================
# L4 序列字典
# ============================================================================

def mine_sequences(
    block_lines: List[List[str]],
    min_len: int = 3,
    max_len: int = 8,
    min_count: int = 2,
) -> Tuple[List[List[str]], List[Tuple[str, Tuple[str, ...]]]]:
    """在归一化指令 token 流上挖宏。

    Returns:
        new_block_lines: 替换后的块行序列（宏引用为独立 token "Pn"）
        macros:          [(Pn, 原始行 tuple)] 按采用顺序
    """
    if not block_lines:
        return block_lines, []

    # 统计候选 n-gram（不跨块）
    counts: Dict[Tuple[str, ...], int] = {}
    for lines in block_lines:
        ln = len(lines)
        for length in range(min_len, max_len + 1):
            if length > ln:
                break
            for i in range(0, ln - length + 1):
                ng = tuple(lines[i:i + length])
                counts[ng] = counts.get(ng, 0) + 1

    candidates = [
        (ng, cnt) for ng, cnt in counts.items() if cnt >= min_count
    ]
    # 节省量 = (len-1)*(count-1)，按 (节省降序, 长度降序, 内容字典序) 确定性排序
    candidates.sort(key=lambda kv: (-(len(kv[0]) - 1) * (kv[1] - 1), -len(kv[0]), kv[0]))

    lines_work = [list(lines) for lines in block_lines]
    macros: List[Tuple[str, Tuple[str, ...]]] = []

    for ng, _cnt in candidates:
        name = f"P{len(macros)}"
        length = len(ng)
        replaced = 0
        new_blocks: List[List[str]] = []
        for lines in lines_work:
            out: List[str] = []
            i = 0
            while i < len(lines):
                if tuple(lines[i:i + length]) == ng:
                    out.append(name)
                    i += length
                    replaced += 1
                else:
                    out.append(lines[i])
                    i += 1
            new_blocks.append(out)
        if replaced >= min_count:
            # 确有 >=2 处非重叠替换才采用该宏，否则回滚（定义本身也有开销）
            lines_work = new_blocks
            macros.append((name, ng))

    return lines_work, macros


# ============================================================================
# L5 地址标签化
# ============================================================================

def assign_labels(blocks: List[Block]) -> None:
    """基本块首地址 → 标签 L0..Ln（块已按地址序构建，entry=L0）。"""
    for i, blk in enumerate(blocks):
        blk.label = f"L{i}"
