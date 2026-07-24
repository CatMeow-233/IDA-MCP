"""SEMZ 文本解析：IDA 导出 / x64dbg trace / 裸文本 → list[Insn]。

支持的行格式（SPEC §2）：
    1. "0x401000: mov rax,1"                       —— 0x 地址 + 冒号
    2. "00401000 | 48:C7C0.. | mov rax,1"          —— x64dbg trace（| 分列：地址|机器码|反汇编|注释）
    3. "401000  mov rax,1"                          —— 裸 hex 地址 + 空白
    4. "mov rax,1"                                  —— 纯指令
    5. ".text:00401000 55                   push rbp" —— IDA listing（段名:地址 + 机器码字节列）

另做两遍标签解析：`loc_401000:` 形式的标签行会映射到下一条指令的地址，
操作数中引用该标签名时改写为 0x 地址。
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from .model import Insn

# "0x401000: mov ..." 或 "00401000: mov ..."
_ADDR_COLON_RE = re.compile(r"^(0[xX][0-9A-Fa-f]+|[0-9A-Fa-f]{6,16})\s*:\s*(.*)$")
# IDA listing：".text:00401000 55                   push rbp"（段名:地址 机器码列 反汇编）
_SEG_ADDR_RE = re.compile(r"^\.[A-Za-z_][\w.$]*:([0-9A-Fa-f]{6,16})\s*(.*)$")
# IDA listing 机器码字节（2 位 hex 一组，后跟空白或行尾）
_BYTE_PAIR_RE = re.compile(r"[0-9A-Fa-f]{2}(?:\s+|$)")
# "401000  mov ..."（裸 hex 地址，>=6 位以避免把 add/dec 等助记符误判为地址）
_ADDR_SPACE_RE = re.compile(r"^([0-9A-Fa-f]{6,16})\s+(.*\S)\s*$")
# "loc_401000:" 标签行
_LABEL_ONLY_RE = re.compile(r"^([A-Za-z_.$][\w.$]*):$")
# x64dbg 机器码列（纯 hex/冒号/空格）
_BYTES_COL_RE = re.compile(r"^[0-9A-Fa-f: ]+$")
# x64dbg 反汇编列中的裸数字一律按 hex 解释（x64dbg 默认十六进制显示）
_BARE_NUM_RE = re.compile(r"(?<![\w.*$])([0-9][0-9A-Fa-f]*)(?![\w.])")
# IDA 地址标签：COLOR_ON + COLOR_ADDR('(') + 16/8 位隐藏 hex 地址载荷
# （IDA UI 与 tag_remove 只显示载荷后的符号名，如 loc_26BC；必须先于通用规则删除，
#  否则载荷会和符号名粘在一起，如 00000000000026BCloc_26BC）
_IDA_ADDR_TAG_RE = re.compile(r"\x01\([0-9A-Fa-f]{16}|\x01\([0-9A-Fa-f]{8}")
# 其余颜色标签：COLOR_ON/COLOR_OFF + 1 字节颜色码
_IDA_TAG_RE = re.compile(r"[\x01\x02].?")
# IDA 自动代码标签操作数：loc_/locret_/jpt_<hex>（可带 short 前缀）。
# generate_disasm_line 对已命名跳转目标渲染符号名而非 hex；不改写则 CFG
# 识别不到目标地址，压缩输出残留内联地址（无 Ln 标签）。hex 至少 5 位，
# 避免 loc_DEAD 这类短名误判。
_IDA_CODE_LABEL_RE = re.compile(r"(?i)^(?:short )?(?:loc|locret|jpt)_([0-9A-F]{5,16})$")


def _rewrite_code_label_ops(ops: List[str]) -> List[str]:
    """IDA 自动代码标签操作数 → 0x 地址（标签内嵌真实地址）。"""
    out: List[str] = []
    for op in ops:
        m = _IDA_CODE_LABEL_RE.match(op.strip())
        if m:
            out.append(f"0x{m.group(1).upper()}")
        else:
            out.append(op)
    return out


def strip_ida_tags(text: str) -> str:
    """剥离 IDA 颜色转义标签（含地址标签的隐藏 hex 载荷）。"""
    return _IDA_TAG_RE.sub("", _IDA_ADDR_TAG_RE.sub("", text))


def _split_ops(ops_text: str) -> List[str]:
    """按逗号切分操作数，忽略 []/() 内部的逗号。"""
    ops: List[str] = []
    depth = 0
    cur: List[str] = []
    for ch in ops_text:
        if ch in "[(":
            depth += 1
        elif ch in "])":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            ops.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        ops.append(tail)
    return [op for op in ops if op]


def _split_mnem_ops(text: str) -> Optional[tuple]:
    text = text.strip()
    if not text:
        return None
    parts = text.split(None, 1)
    mnem = parts[0]
    ops = _split_ops(parts[1]) if len(parts) > 1 else []
    return mnem, ops


def parse_line(line: str, ea: Optional[int] = None) -> Optional[Insn]:
    """解析单行文本为 Insn；无法识别（空行/注释/数据列）返回 None。

    Args:
        line: 原始文本行
        ea:   调用方已知的地址（例如来自 IDA 的 {ea,text} dict），优先采用
    """
    raw = strip_ida_tags(line.rstrip("\n"))
    s = raw.strip()
    if not s or s.startswith(";") or s.startswith("#"):
        return None

    comment: Optional[str] = None

    if "|" in s:
        # x64dbg trace：地址 | 机器码 | 反汇编 [| 注释]
        parts = [p.strip() for p in s.split("|")]
        addr_s = parts[0]
        dis = ""
        if len(parts) >= 3:
            dis = parts[2]
            if len(parts) > 3:
                comment = " | ".join(p for p in parts[3:] if p) or None
        elif len(parts) == 2:
            dis = "" if _BYTES_COL_RE.match(parts[1] or " ") else parts[1]
        if not dis:
            return None
        if ea is None and re.fullmatch(r"(?:0[xX])?[0-9A-Fa-f]+", addr_s or " "):
            ea = int(addr_s, 16)
        # 剥离行内注释并做裸数字 hex 转换
        if ";" in dis:
            dis, _, cmt = dis.partition(";")
            comment = comment or (cmt.strip() or None)
        dis = _BARE_NUM_RE.sub(lambda m: f"0x{int(m.group(1), 16):X}", dis)
        parsed = _split_mnem_ops(dis)
        if parsed is None:
            return None
        mnem, ops = parsed
        return Insn(ea=ea, mnem=mnem, ops=_rewrite_code_label_ops(ops), raw=raw, comment=comment)

    # 剥离尾部注释
    if ";" in s:
        s, _, cmt = s.partition(";")
        s = s.rstrip()
        comment = cmt.strip() or None
        if not s:
            return None

    m = _ADDR_COLON_RE.match(s)
    if m:
        if ea is None:
            ea = int(m.group(1), 0) if m.group(1).lower().startswith("0x") else int(m.group(1), 16)
        s = m.group(2).strip()
    else:
        ms = _SEG_ADDR_RE.match(s)
        if ms:
            # IDA listing：段名:地址 + 机器码字节列 + 反汇编
            if ea is None:
                ea = int(ms.group(1), 16)
            rest = ms.group(2)
            while True:
                bm = _BYTE_PAIR_RE.match(rest)
                if not bm:
                    break
                rest = rest[bm.end():]
            s = rest.strip()
        else:
            m2 = _ADDR_SPACE_RE.match(s)
            if m2:
                if ea is None:
                    ea = int(m2.group(1), 16)
                s = m2.group(2).strip()

    parsed = _split_mnem_ops(s)
    if parsed is None:
        return None
    mnem, ops = parsed
    return Insn(ea=ea, mnem=mnem, ops=_rewrite_code_label_ops(ops), raw=raw, comment=comment)


def parse_text(text: str) -> List[Insn]:
    """解析多行文本为指令列表（两遍：先收集标签，再改写标签操作数）。"""
    # 先整体剥 IDA 颜色标签：\x0b/\x0c 颜色码会被 splitlines 当换行符切碎指令行
    text = strip_ida_tags(text)
    insns: List[Insn] = []
    labels: Dict[str, Optional[int]] = {}
    pending: List[str] = []

    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith(";") or s.startswith("#"):
            continue
        lm = _LABEL_ONLY_RE.match(s)
        if lm and "|" not in s:
            pending.append(lm.group(1))
            continue
        insn = parse_line(line)
        if insn is None:
            continue
        for name in pending:
            labels[name] = insn.ea
        pending = []
        insns.append(insn)

    # 第二遍：操作数中引用的标签名 → 0x 地址
    if labels:
        for insn in insns:
            new_ops: List[str] = []
            for op in insn.ops:
                key = op.strip()
                low = key.lower()
                if key in labels and labels[key] is not None:
                    new_ops.append(f"0x{labels[key]:X}")
                elif low.startswith("offset ") and key[7:].strip() in labels and labels[key[7:].strip()] is not None:
                    new_ops.append(f"offset 0x{labels[key[7:].strip()]:X}")
                else:
                    new_ops.append(op)
            insn.ops = new_ops

    return insns


# ============================================================================
# 架构自动探测（SPEC §5d：arch="auto" 启发式）
# ============================================================================

# ARM64 强特征助记符（x86/x64 不存在）
_ARM64_DETECT_MNEMS = {
    "stp", "ldp", "adrp", "adr", "cbz", "cbnz", "tbz", "tbnz",
    "movz", "movk", "movn", "bl", "blr", "br", "svc", "mrs", "msr",
    "ldur", "stur", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw",
    "strb", "strh", "csel", "csinc", "csinv", "cset", "csetm",
    "dmb", "dsb", "isb", "prfm", "ldxr", "stxr", "ccmp", "ccmn",
}
# ARM64 弱特征（单条不足为据）
_ARM64_DETECT_WEAK = {"ldr", "str"}
# x86/x64 特征助记符
_X64_DETECT_MNEMS = {
    "push", "pop", "call", "jmp", "lea", "movzx", "movsx", "movsxd",
    "retn", "retf", "leave", "enter", "xchg", "cmpxchg", "cpuid",
    "pushf", "popf", "pushfq", "popfq", "loop", "syscall", "sysenter",
    "cdq", "cqo", "cwde", "cdqe", "imul", "idiv", "sete", "setne",
}
# ARM64 寄存器操作数（整词）
_ARM64_OP_REG_RE = re.compile(
    r"(?:[xw](?:[0-9]|[12][0-9]|30)|sp|wsp|xzr|wzr|pc)"
)
# x86 寄存器别名（借用 normalize 的表，惰性导入避免循环）
_X86_ALIAS_LAZY = None


def _x86_alias_re():
    global _X86_ALIAS_LAZY
    if _X86_ALIAS_LAZY is None:
        from .normalize import _ALIAS_REG_RE, _REG_ALIAS, JCC
        _X86_ALIAS_LAZY = (_ALIAS_REG_RE, JCC, _REG_ALIAS)
    return _X86_ALIAS_LAZY


def _detect_bitness(insns: List[Insn]) -> Optional[str]:
    """x64/x86 位宽判定（SPEC §5e）。

    出现任一 64 位寄存器（rax..r15、rip、qword ptr）→ None（x64 路径，现状）；
    否则出现 32 位寄存器（eax..ebp）或 dword ptr → "x86"；都无法判定回退 None（x64）。
    """
    alias_re, _jcc, alias_map = _x86_alias_re()
    has64 = False
    has32 = False
    for ins in insns:
        for op in ins.ops:
            o = op.strip().lower()
            if "qword" in o:
                has64 = True
            elif "dword" in o:
                has32 = True
            for m in alias_re.finditer(o):
                fam, width = alias_map[m.group(0)]
                if width == "q" or fam in ("r8", "r9") or fam.startswith("r1"):
                    has64 = True  # rax..r15 / rip
                elif width == "d":
                    has32 = True  # eax..ebp / eip / rNd（r8d 等已被上一条捕获）
    if has64:
        return None
    return "x86" if has32 else None


def detect_arch(insns: List[Insn]) -> Optional[str]:
    """指令列表的架构启发式探测。

    顺序（SPEC §5e）：先判 ARM64（命中 x29/x30/sp 等寄存器名、`#imm`、
    stp/ldp/adrp/cbz 等助记符、b.cond 条件分支且压过 x86 特征 → "arm64"）；
    再按位宽判 x64/x86（见 _detect_bitness）；无法判定回退 None（x64 路径）。
    """
    alias_re, jcc, _alias_map = _x86_alias_re()
    arm = 0
    x86 = 0
    for ins in insns:
        m = ins.mnem.lower().strip()
        if m in _ARM64_DETECT_MNEMS or m.startswith("b."):
            arm += 3
        elif m in _ARM64_DETECT_WEAK:
            arm += 1
        if m in _X64_DETECT_MNEMS or m in jcc:
            x86 += 2
        for op in ins.ops:
            o = op.strip().lower()
            if "#" in o:
                arm += 2
            if _ARM64_OP_REG_RE.fullmatch(o.lstrip("#")):
                arm += 2
            if " ptr" in o or o.endswith(" ptr"):
                x86 += 2
            elif alias_re.search(o):
                x86 += 1
    if arm >= 3 and arm > x86:
        return "arm64"
    return _detect_bitness(insns)
