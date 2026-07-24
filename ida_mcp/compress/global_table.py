"""SEMZ ultra 全局固定表（SPEC §5c）。

字典全局固定、写进 instructor 文档：ultra 输出**不**携带 #MN/#RG 头部，
实现与测试内嵌同一份表做编码/解码一致性检查。

助记符：m=mov p=push q=pop c=call j=jmp l=lea a=add s=sub x=xor k=cmp t=test
        r=ret n=and o=or h=shl g=shr i=inc d=dec；双码 zx=movzx sx=movsx；
        其余助记符按原样小写拼写。
jcc 条件码：z nz a ae b be g ge l le s ns o no p np（融合形 `g<cc> Ln: k|t ops`）。
寄存器：a=rax b=rbx c=rcx d=rdx e=rsi f=rdi g=rsp h=rbp
        i=r8 j=r9 k=r10 l=r11 m=r12 n=r13 o=r14 p=r15 R=rip；
        宽度：裸写=64 位，后缀 4/2/1 = 32/16/8 位（a4=eax a2=ax a1=al）。
数制：数值字面量一律十六进制、以数字 0-9 开头（0ff=0xff），允许前导 -。
"""
from __future__ import annotations

from typing import Optional

from .normalize import reg_family, reg_width

# 助记符 → 固定短码
MNEMONIC_CODES = {
    "mov": "m", "push": "p", "pop": "q", "call": "c", "jmp": "j",
    "lea": "l", "add": "a", "sub": "s", "xor": "x", "cmp": "k",
    "test": "t", "retn": "r", "and": "n", "or": "o", "shl": "h",
    "shr": "g", "inc": "i", "dec": "d",
    "movzx": "zx", "movsx": "sx",
}

# jcc 条件码（jz→z, jnz→nz, ...；即助记符去掉前导 j）
JCC_CODES = (
    "z", "nz", "a", "ae", "b", "be", "g", "ge",
    "l", "le", "s", "ns", "o", "no", "p", "np",
)

# 寄存器族 → 固定短码
REG_CODES = {
    "rax": "a", "rbx": "b", "rcx": "c", "rdx": "d",
    "rsi": "e", "rdi": "f", "rsp": "g", "rbp": "h",
    "r8": "i", "r9": "j", "r10": "k", "r11": "l",
    "r12": "m", "r13": "n", "r14": "o", "r15": "p",
    "rip": "R",
}

# 宽度标记（normalize 内部 b/w/d/q）→ ultra 后缀
WIDTH_SUFFIX = {"q": "", "d": "4", "w": "2", "b": "1"}
SUFFIX_WIDTH = {"": "q", "4": "d", "2": "w", "1": "b"}

# 内存尺寸标记（normalize `:b/:w/:d/:q` 等）→ ultra 宽度后缀
MEM_SIZE_SUFFIX = {"b": "1", "w": "2", "d": "4", "q": "8"}

# 反向表（解码一致性检查用）
MNEMONIC_NAMES = {v: k for k, v in MNEMONIC_CODES.items()}
REG_NAMES = {v: k for k, v in REG_CODES.items()}

# 高字节寄存器无 4/2/1 编码（a1 与 al 冲突），原样拼写
_HIGH_BYTE_REGS = {"ah", "bh", "ch", "dh"}


def encode_reg(name: str) -> Optional[str]:
    """归一化寄存器名 → ultra 码；非寄存器返回 None。

    GPR 族内：族码 + 宽度后缀（rax→a, eax→a4, ax→a2, al→a1, r8d→i4）。
    高字节寄存器（ah..dh）与 xmm/st/段寄存器等非 GPR：原样小写拼写。
    """
    low = name.lower()
    if low in _HIGH_BYTE_REGS:
        return low
    fam = reg_family(low)
    if fam is None:
        return None
    if fam not in REG_CODES:
        return low  # xmm/st/段寄存器等 best-effort 透传
    width = reg_width(low) or "q"
    return REG_CODES[fam] + WIDTH_SUFFIX.get(width, "")


def ultra_hex(token: str) -> str:
    """归一化 `0x..` 常量 → ultra 十六进制字面量（去 0x、小写、以 0-9 开头）。

    0xFF → 0ff；0x20 → 20；0xA → 0a。
    """
    s = f"{int(token, 16):x}"
    if s[0] in "abcdef":
        s = "0" + s
    return s


# ============================================================================
# ARM64 全局固定表（SPEC §5d）
# ============================================================================

import re as _re  # noqa: E402

from .normalize import arm64_reg_family as _a64_fam  # noqa: E402

# 助记符 → 固定短码（其余助记符按原样小写拼写，ARM64 助记符本已 <=4 字符）
ARM64_MNEMONIC_CODES = {
    "mov": "m", "movz": "z", "movk": "k", "movn": "n",
    "ldr": "l", "str": "s", "ldp": "p", "stp": "q",
    "ldur": "o", "stur": "w",
    "b": "j", "bl": "c", "ret": "r",
    "cmp": "f", "tst": "t", "adrp": "d",
    # 访存变体后缀：b=byte h=half s=sign
    "ldrb": "lb", "ldrh": "lh", "ldrsb": "lsb", "ldrsh": "lsh",
    "ldrsw": "lw", "strb": "sb", "strh": "sh",
}

# 条件码（hs=cs、lo=cc 已在 normalize 归一化）
ARM64_COND_CODES = (
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al",
)

# 移位/扩展后缀（挂在最后源操作数后，可带量如 :u2）
ARM64_SHIFT_SUFFIX = {
    "lsl": "l", "lsr": "r", "asr": "a", "ror": "R",
    "uxtw": "u", "sxtw": "x", "uxtx": "U", "sxtx": "X",
}
ARM64_SUFFIX_SHIFT = {v: k for k, v in ARM64_SHIFT_SUFFIX.items()}

# 反向表（解码一致性检查用）
ARM64_MNEMONIC_NAMES = {v: k for k, v in ARM64_MNEMONIC_CODES.items()}

# 寄存器：a..z=x0..x25，A..E=x26..x30，S=sp，Z=xzr/wzr，P=pc
ARM64_REG_CODES = {f"x{i}": chr(ord("a") + i) for i in range(26)}
ARM64_REG_CODES.update({f"x{i}": chr(ord("A") + i - 26) for i in range(26, 31)})
ARM64_REG_CODES.update({"sp": "S", "xzr": "Z", "pc": "P"})
# 约定：D=x29=fp，E=x30=lr
ARM64_REG_NAMES = {v: k for k, v in ARM64_REG_CODES.items()}

_A64_XW_RE = _re.compile(r"([xw])(\d+)")


def encode_reg_arm64(name: str) -> Optional[str]:
    """ARM64 归一化寄存器名 → ultra 码；非寄存器返回 None。

    裸写=64 位（x0→a），前缀 w=32 位视图（w1→wb）；SIMD/系统寄存器原样小写拼写。
    """
    n = name.lower()
    if n in ("sp", "wsp"):
        return "S" if n == "sp" else "wS"
    if n in ("xzr", "wzr"):
        return "Z" if n == "xzr" else "wZ"
    if n == "pc":
        return "P"
    m = _A64_XW_RE.fullmatch(n)
    if m:
        idx = int(m.group(2))
        if idx > 30:
            return n
        base = ARM64_REG_CODES[f"x{idx}"]
        return base if m.group(1) == "x" else "w" + base
    fam = _a64_fam(n)
    if fam is not None:
        return n  # SIMD 等原样小写拼写
    return None


# ============================================================================
# x86（32 位）全局固定表（SPEC §5e）
# ============================================================================
#
# 族字母同 x64（a..h = eax,ebx,ecx,edx,esi,edi,esp,ebp 族），**裸写 = 32 位**
# （a=eax）；`2`=16 位（a2=ax）；`1`=8 位低字节（a1=al）；R=eip。
# ah..dh 与段寄存器（fs/gs 等）按原样小写拼写；无 r8–r15。
# 助记符表直接复用 x64 的 MNEMONIC_CODES。

# 内部族名（normalize 统一归族到 rax 形）→ 固定短码
X86_REG_CODES = {
    "rax": "a", "rbx": "b", "rcx": "c", "rdx": "d",
    "rsi": "e", "rdi": "f", "rsp": "g", "rbp": "h",
    "rip": "R",  # eip
}

# 宽度标记（normalize 内部 b/w/d）→ ultra 后缀（裸写 = 32 位）
X86_WIDTH_SUFFIX = {"d": "", "w": "2", "b": "1"}
X86_SUFFIX_WIDTH = {"": "d", "2": "w", "1": "b"}

# 内存尺寸标记 → ultra 宽度后缀：x86 默认 dword 无后缀，非 dword 用 8/4/2/1
X86_MEM_SIZE_SUFFIX = {"b": "1", "w": "2", "d": "", "q": "8"}


def encode_reg_x86(name: str) -> Optional[str]:
    """x86 归一化寄存器名 → ultra 码；非寄存器返回 None。

    裸写 = 32 位（eax→a），后缀 2/1 = 16/8 位（ax→a2, al→a1）；
    ah..dh/段寄存器/xmm/st 等原样小写拼写；64 位寄存器（rax/r8..）不应出现，
    出现时按原样透传（best-effort）。
    """
    low = name.lower()
    if low in _HIGH_BYTE_REGS:
        return low
    fam = reg_family(low)
    if fam is None:
        return None
    if fam not in X86_REG_CODES:
        return low  # r8-r15/xmm/st/段寄存器等原样拼写
    width = reg_width(low) or "d"
    if width == "q":
        return low  # 64 位寄存器不属于 x86，原样透传
    return X86_REG_CODES[fam] + X86_WIDTH_SUFFIX.get(width, "")


# ============================================================================
# arch 分派接口
# ============================================================================

def mnemonic_codes(arch: str) -> dict:
    """按架构返回助记符固定码表（x86 复用 x64 表）。"""
    return ARM64_MNEMONIC_CODES if arch == "arm64" else MNEMONIC_CODES


def encode_reg_any(name: str, arch: str = "x64") -> Optional[str]:
    """按架构分派寄存器编码。"""
    if arch == "arm64":
        return encode_reg_arm64(name)
    if arch == "x86":
        return encode_reg_x86(name)
    return encode_reg(name)
