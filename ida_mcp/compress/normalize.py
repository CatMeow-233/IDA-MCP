"""SEMZ 归一化与 x86/x64 指令语义属性（纯 Python）。

归一化规则（SPEC §1.2）：
    - 统一小写；hex 统一为 0x 大写无前导零；`1234h`/十进制 → 0x 形式
    - 尺寸修饰 `dword ptr` → 操作数尾部 `:d`（b/w/d/q/x/y/z/t/o）
    - 寄存器别名归族（al/ax/eax/rax → 族 rax，宽度标记保留供 L2 编码）
    - `rep movsb` 类前缀并入助记符 token（`rep_movsb`）

语义属性函数供 liveness 与 cfg 使用：
    regs_read / regs_written / flags_written / is_call / is_branch / is_indirect
未知助记符保守处理：假定读写全部操作数、写标志、有副作用（永不删除）。
"""
from __future__ import annotations

import re
from typing import Optional, Set, Tuple

from .model import Insn

# ============================================================================
# 寄存器族
# ============================================================================

# (family, q, d, w, b-low, b-high)
_FAMILY_DEFS = [
    ("rax", "rax", "eax", "ax", "al", "ah"),
    ("rbx", "rbx", "ebx", "bx", "bl", "bh"),
    ("rcx", "rcx", "ecx", "cx", "cl", "ch"),
    ("rdx", "rdx", "edx", "dx", "dl", "dh"),
    ("rsi", "rsi", "esi", "si", "sil", None),
    ("rdi", "rdi", "edi", "di", "dil", None),
    ("rsp", "rsp", "esp", "sp", "spl", None),
    ("rbp", "rbp", "ebp", "bp", "bpl", None),
] + [
    (f"r{i}", f"r{i}", f"r{i}d", f"r{i}w", f"r{i}b", None) for i in range(8, 16)
] + [
    ("rip", "rip", "eip", "ip", None, None),
]

_REG_ALIAS: dict = {}        # alias -> (family, width)  width ∈ {q,d,w,b}
_REG_CANON: dict = {}        # (family, width) -> 代表别名
for _fam, _q, _d, _w, _b, _h in _FAMILY_DEFS:
    for _alias, _width in ((_q, "q"), (_d, "d"), (_w, "w"), (_b, "b"), (_h, "b")):
        if _alias:
            _REG_ALIAS[_alias] = (_fam, _width)
            _REG_CANON.setdefault((_fam, _width), _alias)

GPR_FAMILIES: Set[str] = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
}

_GENERIC_REG_RE = re.compile(
    r"\b(?:[xyz]mm\d+|mm\d+|st\d*|cr\d+|dr\d+|tr\d+|k[0-7]|[cdefgs]s)\b"
)
_ALIAS_REG_RE = re.compile(
    r"\b(?:" + "|".join(sorted(map(re.escape, _REG_ALIAS), key=len, reverse=True)) + r")\b"
)


def reg_family(name: str) -> Optional[str]:
    """寄存器名 → 族名（rax/.../r15/rip；xmm0 等返回自身族）。"""
    name = name.lower()
    hit = _REG_ALIAS.get(name)
    if hit:
        return hit[0]
    if _GENERIC_REG_RE.fullmatch(name):
        return name
    return None


def reg_width(name: str) -> Optional[str]:
    """寄存器名 → 宽度标记（q/d/w/b；非 GPR 返回 None）。"""
    hit = _REG_ALIAS.get(name.lower())
    return hit[1] if hit else None


def is_register(token: str) -> bool:
    return reg_family(token) is not None


def op_registers(op: str) -> Set[str]:
    """操作数字符串中出现的全部寄存器族。"""
    out: Set[str] = set()
    for m in _ALIAS_REG_RE.finditer(op):
        fam = _REG_ALIAS[m.group(0)][0]
        out.add(fam)
    for m in _GENERIC_REG_RE.finditer(op):
        out.add(m.group(0))
    return out


def is_reg_op(op: str) -> bool:
    return is_register(op.strip())


def is_mem_op(op: str) -> bool:
    return "[" in op


# ============================================================================
# 助记符分类表
# ============================================================================

_PREFIXES = {"rep", "repe", "repne", "repz", "repnz", "lock"}

_MNEM_ALIAS = {
    "ret": "retn", "sal": "shl", "movabs": "mov",
    "je": "jz", "jne": "jnz", "jc": "jb", "jnc": "jae",
    "jnae": "jb", "jnb": "jae", "jna": "jbe", "jnbe": "ja",
    "jnge": "jl", "jnl": "jge", "jng": "jle", "jnle": "jg",
    "jpe": "jp", "jpo": "jnp",
}

JCC: Set[str] = {
    "jo", "jno", "jb", "jae", "jz", "jnz", "jbe", "ja", "js", "jns",
    "jp", "jnp", "jl", "jge", "jle", "jg", "jcxz", "jecxz", "jrcxz",
}
_LOOP = {"loop", "loope", "loopne", "loopz", "loopnz"}
_RET = {"retn", "retf", "iret", "iretd", "iretq"}
_SYS = {"syscall", "sysenter", "sysexit", "sysret", "int", "int1", "int3", "into", "ud2", "hlt", "iret", "iretd", "iretq"}
_PADDING = {"nop", "endbr64", "endbr32", "fnop", "pause"}

_MOV_LIKE = {"mov", "movzx", "movsx", "movsxd"}
_BINOP = {"add", "sub", "and", "or", "xor", "shl", "shr", "sar", "rol", "ror", "xadd", "btc", "btr", "bts"}
_BINOP_FLAGS_READ = {"adc", "sbb", "rcl", "rcr"}
_CMP_LIKE = {"cmp", "test"}
_UNARY_FLAGS = {"inc", "dec", "neg"}
_UNARY_NOFLAGS = {"not"}
_MUL1 = {"mul", "div", "idiv"}  # imul 按操作数个数分派
_CMOV = {f"cmov{cc}" for cc in (
    "o", "no", "b", "ae", "z", "nz", "be", "a", "s", "ns",
    "p", "np", "l", "ge", "le", "g", "c", "nc", "e", "ne",
    "nae", "nb", "nbe", "nge", "nl", "nle", "pe", "po",
)}
_SETCC = {f"set{cc}" for cc in (
    "o", "no", "b", "ae", "z", "nz", "be", "a", "s", "ns",
    "p", "np", "l", "ge", "le", "g", "c", "nc", "e", "ne",
    "nae", "nb", "nbe", "nge", "nl", "nle", "pe", "po",
)}
_CONVERT = {"cbw", "cwde", "cdqe"}          # rw rax
_CONVERT2 = {"cwd", "cdq", "cqo"}          # rw rax,rdx
_BSWAP = {"bswap", "xchg"}                 # 单独处理 xchg


# ============================================================================
# 指令语义属性
# ============================================================================

def is_call(insn: Insn, arch: str = "x64") -> bool:
    if arch == "arm64":
        return insn.mnem in _ARM64_CALLS
    return insn.mnem.startswith("call")


def is_branch(insn: Insn, arch: str = "x64") -> bool:
    if arch == "arm64":
        m = insn.mnem
        return m in _ARM64_UNCOND_BR or m in _ARM64_CBR or m in _ARM64_COND_BR
    return insn.mnem == "jmp" or insn.mnem in JCC or insn.mnem in _LOOP


def is_indirect(insn: Insn, arch: str = "x64") -> bool:
    """jmp/call 的目标不是纯 0x 立即数（寄存器或内存间接）。"""
    if arch == "arm64":
        return insn.mnem in _ARM64_INDIRECT
    if not (is_branch(insn) or is_call(insn)):
        return False
    if not insn.ops:
        return True
    return re.fullmatch(r"0x[0-9A-F]+", insn.ops[0]) is None


def branch_target_index(insn: Insn, arch: str = "x64") -> int:
    """分支/调用指令的目标操作数下标（cbz/tbz 的目标不在首位）。"""
    if arch == "arm64":
        if insn.mnem in ("cbz", "cbnz"):
            return 1
        if insn.mnem in ("tbz", "tbnz"):
            return 2
    return 0


def _rw(op: str) -> Tuple[Set[str], Set[str], bool]:
    """操作数读写拆分：返回 (地址/源读寄存器, 写寄存器, 是否内存写目标)。"""
    if is_reg_op(op):
        fam = reg_family(op.strip())
        return set(), {fam}, False  # type: ignore
    if is_mem_op(op):
        return op_registers(op), set(), True
    return op_registers(op), set(), False


def access(insn: Insn, arch: str = "x64") -> dict:
    """指令的保守语义访问集。

    返回 dict:
        reads      寄存器读集合
        writes     寄存器写集合
        flags_r    是否读标志位
        flags_w    是否写标志位
        mem_write  是否写内存
        side       是否有副作用（call/jmp/push/pop/系统指令/内存写等，永不删除）
    """
    if arch == "arm64":
        return _access_arm64(insn)
    m = insn.mnem
    ops = insn.ops
    reads: Set[str] = set()
    writes: Set[str] = set()
    flags_r = False
    flags_w = False
    mem_write = False
    side = False

    def dst_rw(i: int) -> None:
        nonlocal mem_write
        if i < len(ops):
            r, w, mw = _rw(ops[i])
            reads.update(r)
            writes.update(w)
            mem_write = mem_write or mw

    def src_read(i: int) -> None:
        if i < len(ops):
            reads.update(op_registers(ops[i]))

    if m in _PADDING:
        pass
    elif m in _MOV_LIKE:
        src_read(1)
        dst_rw(0)
    elif m == "lea":
        src_read(1)  # 仅地址计算寄存器，不读内存
        if ops and is_reg_op(ops[0]):
            writes.add(reg_family(ops[0].strip()))  # type: ignore
    elif m == "xchg":
        dst_rw(0)
        dst_rw(1)
        src_read(0)
        src_read(1)
    elif m in _BINOP or m in _BINOP_FLAGS_READ:
        src_read(0)
        src_read(1)
        dst_rw(0)
        flags_w = True
        flags_r = m in _BINOP_FLAGS_READ
    elif m in _CMP_LIKE:
        src_read(0)
        src_read(1)
        flags_w = True
    elif m in _UNARY_FLAGS:
        src_read(0)
        dst_rw(0)
        flags_w = True
    elif m in _UNARY_NOFLAGS:
        src_read(0)
        dst_rw(0)
    elif m in _MUL1:
        src_read(0)
        reads.update({"rax", "rdx"})
        writes.update({"rax", "rdx"})
        flags_w = True
    elif m == "imul":
        if len(ops) <= 1:
            src_read(0)
            reads.update({"rax"})
            writes.update({"rax", "rdx"})
        elif len(ops) == 2:
            src_read(0)
            src_read(1)
            dst_rw(0)
        else:
            src_read(1)
            src_read(2)
            dst_rw(0)
        flags_w = True
    elif m == "push" or m == "pushf" or m == "pushfq" or m == "pushfd":
        src_read(0) if m == "push" else None
        reads.add("rsp")
        writes.add("rsp")
        mem_write = True
        side = True
        flags_r = m != "push"
    elif m == "pop" or m == "popf" or m == "popfq" or m == "popfd":
        reads.add("rsp")
        writes.add("rsp")
        if m == "pop":
            if ops and is_reg_op(ops[0]):
                writes.add(reg_family(ops[0].strip()))  # type: ignore
            elif ops and is_mem_op(ops[0]):
                mem_write = True
                reads.update(op_registers(ops[0]))
        else:
            flags_w = True
        side = True
    elif is_call(insn):
        # 保守屏障：读写全部 GPR（参数/返回值/调用者保存），副作用
        reads.update(GPR_FAMILIES)
        writes.update(GPR_FAMILIES)
        src_read(0)
        side = True
    elif m == "jmp":
        src_read(0)
        side = True
    elif m in JCC or m in _LOOP:
        flags_r = True
        if m in ("jcxz", "jecxz", "jrcxz") or m in _LOOP:
            reads.add("rcx")
        side = True
    elif m in _RET:
        # 保守屏障：返回值/栈等全部寄存器视为被读
        reads.update(GPR_FAMILIES)
        side = True
    elif m == "leave":
        reads.update({"rbp", "rsp"})
        writes.update({"rbp", "rsp"})
        side = True
    elif m == "enter":
        reads.update({"rbp", "rsp"})
        writes.update({"rbp", "rsp"})
        mem_write = True
        side = True
    elif m in _SYS or m == "cpuid":
        reads.update(GPR_FAMILIES)
        writes.update(GPR_FAMILIES)
        flags_w = True
        side = True
    elif m == "lahf":
        flags_r = True
        writes.add("rax")
    elif m == "sahf":
        reads.add("rax")
        flags_w = True
    elif m in _CMOV:
        src_read(0)
        src_read(1)
        dst_rw(0)
        flags_r = True
    elif m in _SETCC:
        dst_rw(0)
        flags_r = True
    elif m in _CONVERT:
        reads.add("rax")
        writes.add("rax")
    elif m in _CONVERT2:
        reads.update({"rax", "rdx"})
        writes.update({"rax", "rdx"})
    elif m == "bswap":
        src_read(0)
        dst_rw(0)
    elif _is_string_op(m):
        reads, writes, flags_w, mem_write, side = _string_op_access(m)
    else:
        # 未知助记符：保守处理 —— 读写全部操作数、写标志、有副作用
        for op in ops:
            reads.update(op_registers(op))
            if is_reg_op(op):
                writes.add(reg_family(op.strip()))  # type: ignore
            elif is_mem_op(op):
                mem_write = True
        flags_w = True
        side = True

    if mem_write:
        side = True

    return {
        "reads": reads,
        "writes": writes,
        "flags_r": flags_r,
        "flags_w": flags_w,
        "mem_write": mem_write,
        "side": side,
    }


def _is_string_op(m: str) -> bool:
    base = m
    for p in ("repne_", "repnz_", "repe_", "repz_", "rep_", "lock_"):
        if base.startswith(p):
            base = base[len(p):]
            break
    return base.startswith(("movs", "stos", "lods", "scas", "cmps"))


def _string_op_access(m: str) -> Tuple[Set[str], Set[str], bool, bool, bool]:
    base = m
    rep = False
    for p in ("repne_", "repnz_", "repe_", "repz_", "rep_", "lock_"):
        if base.startswith(p):
            rep = True
            base = base[len(p):]
            break
    reads: Set[str] = set()
    writes: Set[str] = set()
    flags_w = False
    mem_write = False
    side = False
    if base.startswith("movs"):
        reads.update({"rsi", "rdi"})
        writes.update({"rsi", "rdi"})
        mem_write = True
        side = True
    elif base.startswith("stos"):
        reads.update({"rax", "rdi"})
        writes.add("rdi")
        mem_write = True
        side = True
    elif base.startswith("lods"):
        reads.add("rsi")
        writes.update({"rax", "rsi"})
    elif base.startswith("scas"):
        reads.update({"rax", "rdi"})
        writes.add("rdi")
        flags_w = True
    elif base.startswith("cmps"):
        reads.update({"rsi", "rdi"})
        writes.update({"rsi", "rdi"})
        flags_w = True
    if rep:
        reads.add("rcx")
        writes.add("rcx")
    return reads, writes, flags_w, mem_write, side


def regs_read(insn: Insn, arch: str = "x64") -> Set[str]:
    return access(insn, arch)["reads"]


def regs_written(insn: Insn, arch: str = "x64") -> Set[str]:
    return access(insn, arch)["writes"]


def flags_written(insn: Insn, arch: str = "x64") -> Set[str]:
    """写标志位的指令返回 {"F"}（聚合标志实体），否则空集。"""
    return {"F"} if access(insn, arch)["flags_w"] else set()


def flags_read(insn: Insn, arch: str = "x64") -> Set[str]:
    return {"F"} if access(insn, arch)["flags_r"] else set()


def has_side_effect(insn: Insn, arch: str = "x64") -> bool:
    return access(insn, arch)["side"]


def is_padding(insn: Insn, arch: str = "x64") -> bool:
    if arch == "arm64":
        return insn.mnem in _ARM64_PADDING
    return insn.mnem in _PADDING


# ============================================================================
# 归一化
# ============================================================================

_SIZE_WORDS = {
    "byte": "b", "word": "w", "dword": "d", "qword": "q",
    "xmmword": "x", "ymmword": "y", "zmmword": "z",
    "tbyte": "t", "oword": "o",
}
_DROP_WORDS = {"ptr", "offset", "short", "near", "far", "large", "flat"}
_SEG_PREFIX_RE = re.compile(r"^[cdefgs]s:$")

_HEX_PREF_RE = re.compile(r"(?<![\w.])0[xX][0-9A-Fa-f]+")
_HEX_H_RE = re.compile(r"(?<![\w.])([0-9][0-9A-Fa-f]*)[hH](?![\w])")
_DEC_RE = re.compile(r"(?<![\w.*xX$])(\d+)(?![\w.])")

# x86 段前缀内存（SPEC §5e）：`fs:[30h]` / `large dword ptr fs:30h` → `[fs+0x30]`
# 仅匹配括号/数值形态；`ds:_imp__X` 等标识符形态保持原样（非内存立即数引用）。
_SEG_MEM_PREF_RE = re.compile(
    r"^([cdefgs]s):(\[.*\]|0[xX][0-9A-Fa-f]+|[0-9][0-9A-Fa-f]*[hH]?)$"
)


def _normalize_op(op: str, arch: str = "x64") -> str:
    s = op.strip().lower()
    size: Optional[str] = None
    seg: Optional[str] = None
    kept = []
    for wd in s.split():
        if wd in _SIZE_WORDS and size is None:
            size = _SIZE_WORDS[wd]
            continue
        if wd in _DROP_WORDS:
            continue
        if arch == "x86" and seg is None:
            sm = _SEG_MEM_PREF_RE.match(wd)
            if sm:
                seg = sm.group(1)
                if sm.group(2):
                    kept.append(sm.group(2))
                continue
        if _SEG_PREFIX_RE.match(wd):
            continue
        kept.append(wd)
    s = "".join(kept)  # 去除全部空白，得到规范形 [rbp-0x4]:d
    s = _HEX_H_RE.sub(lambda m: f"0x{int(m.group(1), 16):X}", s)
    s = _HEX_PREF_RE.sub(lambda m: f"0x{int(m.group(0), 16):X}", s)
    s = _DEC_RE.sub(lambda m: f"0x{int(m.group(1)):X}", s)
    if seg is not None:
        # 段前缀移入括号：[fs+0x30]（ultra 输出 `[fs+30]` 形态）
        inner = s[1:-1] if s.startswith("[") and s.endswith("]") else s
        s = f"[{seg}+{inner}]" if inner else f"[{seg}]"
    if size and "[" in s:
        s = f"{s}:{size}"
    return s


def normalize_insn(insn: Insn, arch: str = "x64") -> Insn:
    """归一化一条指令（小写、hex、尺寸修饰、前缀并入、助记符别名）。"""
    if arch == "arm64":
        return _normalize_insn_arm64(insn)
    mnem = insn.mnem.lower().strip()
    ops = list(insn.ops)
    if mnem in _PREFIXES and ops:
        mnem = f"{mnem}_{ops[0].lower().strip()}"
        ops = ops[1:]
    mnem = _MNEM_ALIAS.get(mnem, mnem)
    nops = [_normalize_op(op, arch) for op in ops]
    return Insn(ea=insn.ea, mnem=mnem, ops=nops, raw=insn.raw, comment=insn.comment)


# ============================================================================
# ARM64（SPEC §5d）：寄存器族 / 归一化 / 语义访问表
# ============================================================================

# 条件码（hs=cs、lo=cc 归一化）
ARM64_CONDS = (
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al",
)
_ARM64_COND_ALIAS = {"hs": "cs", "lo": "cc"}

# 寄存器：x0..x30 / w0..w30 / sp / wsp / xzr / wzr / pc / SIMD(v q d s h b 0..31)
_ARM64_REG_FULL_RE = re.compile(
    r"(?:[xw](?:[0-9]|[12][0-9]|30)|sp|wsp|xzr|wzr|pc|[vdqshb](?:[0-9]|[12][0-9]|3[01]))"
)
_ARM64_REG_FIND_RE = re.compile(
    r"\b(?:[xw](?:[0-9]|[12][0-9]|30)|wsp|sp|xzr|wzr|pc|[vdqshb](?:[0-9]|[12][0-9]|3[01]))\b"
)

ARM64_GPR_FAMILIES: Set[str] = {f"x{i}" for i in range(31)} | {"sp"}

_ARM64_PADDING = {"nop", "hint"}
_ARM64_UNCOND_BR = {"b", "br"}
_ARM64_CBR = {"cbz", "cbnz", "tbz", "tbnz"}
_ARM64_COND_BR = {f"b.{c}" for c in ARM64_CONDS}
_ARM64_CALLS = {"bl", "blr"}
_ARM64_INDIRECT = {"br", "blr"}
_ARM64_RET = {"ret", "retaa", "retab"}
_ARM64_SIDE_SYS = {"svc", "hvc", "smc", "mrs", "msr", "dmb", "dsb", "isb", "prfm", "hlt", "brk"}

# 标志消费者：b.cond / csel 族 / adc/sbc
_ARM64_FLAG_READERS = {
    "csel", "csinc", "csinv", "cset", "csetm", "cneg", "cinc", "cinv",
    "adc", "sbc", "adcs", "sbcs", "ccmp", "ccmn", "fcsel",
} | _ARM64_COND_BR

# 常规 ALU（写 op0、读 op1..，无内存/副作用）
_ARM64_ALU = {
    "add", "sub", "and", "orr", "eor", "bic", "eon", "orn",
    "lsl", "lsr", "asr", "ror", "mul", "mneg", "neg", "mvn",
    "udiv", "sdiv", "lslv", "lsrv", "asrv", "rorv",
    "clz", "cls", "rbit", "rev", "rev16", "rev32",
    "sxtw", "uxtw", "sxth", "uxth", "sxtb", "uxtb",
    "extr", "bfm", "ubfm", "sbfm", "bfi", "bfxil", "sbfx", "ubfx",
    "madd", "msub", "smulh", "umulh",
}


def arm64_reg_family(name: str) -> Optional[str]:
    """ARM64 寄存器名 → 族名。w 视图归入对应 x 族（写 wN = 写整个 xN 族）。"""
    n = name.lower()
    if n in ("sp", "wsp"):
        return "sp"
    if n in ("xzr", "wzr"):
        return "xzr"
    if n == "pc":
        return "pc"
    if _ARM64_REG_FULL_RE.fullmatch(n):
        if n[0] in "xw":
            return f"x{int(n[1:])}"
        return f"v{int(n[1:])}"  # SIMD 各视图同族
    return None


def is_register_arm64(token: str) -> bool:
    return arm64_reg_family(token) is not None


def arm64_op_registers(op: str) -> Set[str]:
    """ARM64 操作数字符串中出现的全部寄存器族。"""
    out: Set[str] = set()
    for m in _ARM64_REG_FIND_RE.finditer(op):
        fam = arm64_reg_family(m.group(0))
        if fam is not None:
            out.add(fam)
    return out


def _arm64_first_reg(op: str) -> Optional[str]:
    m = _ARM64_REG_FIND_RE.search(op)
    return arm64_reg_family(m.group(0)) if m else None


def _arm64_flag_writer(m: str) -> bool:
    """只有 S 后缀指令与 cmp/cmn/tst（及 ccmp 族/adcs/sbcs）写标志。"""
    if m in ("cmp", "cmn", "tst", "ccmp", "ccmn", "adcs", "sbcs"):
        return True
    return m.endswith("s") and m[:-1] in _ARM64_ALU


def _access_arm64(insn: Insn) -> dict:
    """ARM64 保守语义访问集（SPEC §5d normalize/liveness 规则）。"""
    m = insn.mnem
    ops = insn.ops
    reads: Set[str] = set()
    writes: Set[str] = set()
    flags_r = False
    flags_w = False
    mem_write = False
    side = False

    def rd(i: int) -> None:
        if i < len(ops):
            reads.update(arm64_op_registers(ops[i]))

    def wr_reg(i: int) -> None:
        if i < len(ops):
            fam = arm64_reg_family(ops[i].strip())
            if fam is not None:
                writes.add(fam)

    # 预/后索引写回基址寄存器（基址是被定义的）
    wb: Optional[str] = None
    for op in ops:
        if op.endswith("]!"):
            wb = _arm64_first_reg(op)
            break
    if wb is None and len(ops) >= 2 and ops[-2].endswith("]") \
            and re.fullmatch(r"-?0x[0-9A-F]+", ops[-1]):
        wb = _arm64_first_reg(ops[-2])

    if m in _ARM64_PADDING:
        pass
    elif m in ("mov", "movz", "movn"):
        rd(1)
        wr_reg(0)
    elif m == "movk":
        rd(0)  # 保位写入，保守读旧值
        rd(1)
        wr_reg(0)
    elif m in ("cmp", "cmn", "tst"):
        for i in range(len(ops)):
            rd(i)
        flags_w = True  # 无目的寄存器，只写标志
    elif m in ("adrp", "adr"):
        wr_reg(0)
    elif m in ("ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw", "ldur",
               "ldxr", "ldaxr", "ldrb", "ldtr"):
        wr_reg(0)
        rd(1)
        if wb:
            writes.add(wb)
    elif m in ("str", "strb", "strh", "stur", "stxr", "stlxr", "sttr"):
        rd(0)
        rd(1)
        mem_write = True
        if wb:
            writes.add(wb)
    elif m == "ldp":
        wr_reg(0)
        wr_reg(1)
        rd(2)
        if wb:
            writes.add(wb)
    elif m == "stp":
        rd(0)
        rd(1)
        rd(2)
        mem_write = True
        if wb:
            writes.add(wb)
    elif m == "b":
        side = True
    elif m in _ARM64_COND_BR:
        flags_r = True
        side = True
    elif m in _ARM64_CBR:
        rd(0)
        side = True
    elif m == "br":
        rd(0)
        side = True
    elif m == "bl":
        # 保守：读 x0-x7（参数），写 x0（返回值）与 x30(lr)
        reads.update({f"x{i}" for i in range(8)})
        writes.update({"x0", "x30"})
        side = True
    elif m == "blr":
        reads.update({f"x{i}" for i in range(8)})
        rd(0)  # 额外读目标寄存器
        writes.update({"x0", "x30"})
        side = True
    elif m in _ARM64_RET:
        reads.update({"x30", "x0"})
        rd(0)
        side = True
    elif m in _ARM64_FLAG_READERS:
        flags_r = True
        rd(1)
        rd(2)
        wr_reg(0)
        flags_w = m in ("adcs", "sbcs", "ccmp", "ccmn")
    elif m in _ARM64_SIDE_SYS:
        # 副作用保守全集，永不消除
        reads.update(ARM64_GPR_FAMILIES)
        writes.update(ARM64_GPR_FAMILIES)
        flags_w = True
        side = True
    elif m in _ARM64_ALU or (m.endswith("s") and m[:-1] in _ARM64_ALU):
        wr_reg(0)
        for i in range(1, len(ops)):
            rd(i)
        flags_w = _arm64_flag_writer(m)
    else:
        # 未知助记符：保守处理 —— 读写全部操作数、写标志、有副作用（同 x64 策略）
        for op in ops:
            reads.update(arm64_op_registers(op))
            fam = arm64_reg_family(op.strip())
            if fam is not None:
                writes.add(fam)
            elif "[" in op:
                mem_write = True
        flags_w = True
        side = True

    if mem_write:
        side = True

    return {
        "reads": reads,
        "writes": writes,
        "flags_r": flags_r,
        "flags_w": flags_w,
        "mem_write": mem_write,
        "side": side,
    }


# ============================================================================
# ARM64 归一化（SPEC §5d：小写化、去 #、hs→cs/lo→cc）
# ============================================================================

_ARM64_NUM_TOKEN_RE = re.compile(r"-?(?:0[xX][0-9A-Fa-f]+|[0-9][0-9A-Fa-f]*[hH]|\d+)")
_ARM64_SHIFT_SPEC_RE = re.compile(r"^(lsl|lsr|asr|ror|uxtw|sxtw|uxtx|sxtx)(\s+\S+)?$")


def _arm64_norm_num(token: str) -> str:
    """`#0x50` / `#-80` / `50h` / `80` → `0x50` / `-0x50`（无前缀标识符不动）。"""
    s = token.strip()
    if not _ARM64_NUM_TOKEN_RE.fullmatch(s):
        return s
    neg = s.startswith("-")
    body = s[1:] if neg else s
    try:
        if body.lower().startswith("0x"):
            val = int(body, 16)
        elif body.lower().endswith("h"):
            val = int(body[:-1], 16)
        else:
            val = int(body, 10)
    except ValueError:
        return s
    return f"-0x{val:X}" if neg else f"0x{val:X}"


def _normalize_op_arm64(op: str) -> str:
    s = op.strip().lower().replace("#", "")
    # 寄存器别名归族：fp→x29, lr→x30
    if s == "fp":
        return "x29"
    if s == "lr":
        return "x30"
    if "[" in s:
        bang = s.endswith("!")
        if bang:
            s = s[:-1].rstrip()
        i = s.index("[")
        j = s.rindex("]")
        inner = s[i + 1:j]
        parts = [p.strip() for p in inner.split(",") if p.strip()]
        nparts: List[str] = []
        for p in parts:
            if p in ("fp", "lr"):
                p = {"fp": "x29", "lr": "x30"}[p]
            elif " " in p:
                p = " ".join(_arm64_norm_num(t) for t in p.split())
            else:
                p = _arm64_norm_num(p)
            nparts.append(p)
        if nparts:
            content = nparts[0]
            for p in nparts[1:]:
                content += p if p.startswith("-") else "+" + p
        else:
            content = ""
        return s[:i] + "[" + content + "]" + ("!" if bang else "")
    if " " in s:
        return " ".join(_arm64_norm_num(t) for t in s.split())
    return _arm64_norm_num(s)


def _normalize_insn_arm64(insn: Insn) -> Insn:
    """ARM64 归一化：小写化、去 `#`、条件码 hs→cs/lo→cc、fp/lr 归族。"""
    mnem = insn.mnem.lower().strip()
    if "." in mnem:
        base, _, cond = mnem.partition(".")
        mnem = f"{base}.{_ARM64_COND_ALIAS.get(cond, cond)}"
    ops = [_normalize_op_arm64(op) for op in insn.ops]
    if ops:
        last = ops[-1]
        if last in ARM64_CONDS or last in _ARM64_COND_ALIAS:
            ops[-1] = _ARM64_COND_ALIAS.get(last, last)
    return Insn(ea=insn.ea, mnem=mnem, ops=ops, raw=insn.raw, comment=insn.comment)
