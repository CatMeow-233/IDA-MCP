"""SEMZ v1 语义压缩纯 Python 单测（无 IDA 可跑）。

语料（SPEC §5）：
    A. 含序言/分支/循环的小函数（~30 指令）
    B. 含 3 个相似 handler（>=6 条指令重复骨架）的 VM 风格片段
    C. 含死代码（mov rax,1; mov rax,2、cmp 后标志被覆盖等）
    D. x64dbg trace 文本格式
"""
from __future__ import annotations

import os
import re
import sys

import pytest

# 确保 ida_mcp 包可导入（与 test/conftest.py 同样的 sys.path 处理）
_pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _pkg_root not in sys.path:
    sys.path.insert(0, _pkg_root)

from ida_mcp.compress import compress_insns, compress_text, CompressError  # noqa: E402
from ida_mcp.compress.parse import parse_text  # noqa: E402


# ============================================================================
# 语料
# ============================================================================

CORPUS_A = """\
0x401000: push rbp
0x401001: mov rbp, rsp
0x401004: sub rsp, 0x30
0x401008: mov dword ptr [rbp-0x4], 0
0x40100F: mov dword ptr [rbp-0x8], 0
0x401016: mov dword ptr [rbp-0xC], 1
0x40101D: jmp 0x401040
0x401022: mov eax, dword ptr [rbp-0x8]
0x401029: add eax, dword ptr [rbp-0x4]
0x401030: mov dword ptr [rbp-0x8], eax
0x401033: mov eax, dword ptr [rbp-0xC]
0x40103A: add dword ptr [rbp-0x4], eax
0x40103D: add dword ptr [rbp-0xC], 1
0x401040: cmp dword ptr [rbp-0xC], 0xA
0x401047: jl 0x401022
0x401049: cmp dword ptr [rbp-0x8], 0x32
0x401050: jle 0x401060
0x401052: mov ecx, dword ptr [rbp-0x8]
0x401059: call 0x402000
0x40105E: jmp 0x401068
0x401060: mov ecx, dword ptr [rbp-0x4]
0x401067: call 0x402000
0x401068: mov eax, dword ptr [rbp-0x8]
0x40106F: mov rsp, rbp
0x401072: pop rbp
0x401073: retn
"""

# 3 个 handler 共享同一 6 指令骨架（VM 风格 dispatch），各带 1 条区分指令
_HANDLER_SKEL = """\
mov rax, qword ptr [r12]
add r12, 8
movzx ecx, al
shl rcx, 4
lea rdx, qword ptr [r13+rcx]
jmp qword ptr [rdx]
"""

_CORPUS_B_LINES = []
_ea = 0x500000
for _unique in ("xor r8, r8", "xor r9, r9", "xor r10, r10"):
    for _line in _HANDLER_SKEL.strip().splitlines() + [_unique]:
        _CORPUS_B_LINES.append(f"0x{_ea:X}: {_line}")
        _ea += 7
CORPUS_B = "\n".join(_CORPUS_B_LINES) + "\n"

CORPUS_C = """\
0x600000: push rbp
0x600001: mov rbp, rsp
0x600004: mov rax, 1
0x60000B: mov rax, 2
0x600012: cmp rax, 5
0x600019: xor rcx, rcx
0x60001C: jz 0x600030
0x60001E: mov rbx, rax
0x600021: mov rbx, rcx
0x600030: mov rax, rbx
0x600033: pop rbp
0x600034: retn
"""

CORPUS_D = """\
00401000 | 55               | push rbp
00401001 | 48:8BEC          | mov rbp, rsp
00401004 | 48:83EC20        | sub rsp, 20
00401008 | 48:8D0D12340000  | lea rcx, [rip+0x3412]
0040100F | E8EC0F0000       | call 402000
00401014 | 33C0             | xor eax, eax
00401016 | 48:8BE5          | mov rsp, rbp
00401019 | 5D               | pop rbp
0040101A | C3               | ret
"""

ALL_CORPORA = {"A": CORPUS_A, "B": CORPUS_B, "C": CORPUS_C, "D": CORPUS_D}


# ============================================================================
# 断言辅助
# ============================================================================

def _body_lines(text: str):
    """非 # 头的输出行（标签行/指令行）。"""
    return [ln for ln in text.splitlines() if not ln.startswith("#")]


def _defined_labels(text: str):
    return set(re.findall(r"^(L\d+):", text, flags=re.M))


def _referenced_labels(text: str):
    refs = set()
    for ln in _body_lines(text):
        if ln.lstrip().startswith(("L",)) and ln.rstrip().endswith(":"):
            continue
        refs.update(re.findall(r"\b(L\d+)\b", ln))
    return refs


def _defined_macros(text: str):
    return set(re.findall(r"^#SQ (P\d+)=", text, flags=re.M))


def _referenced_macros(text: str):
    refs = set()
    for ln in _body_lines(text):
        s = ln.strip()
        if re.fullmatch(r"P\d+", s):
            refs.add(s)
    return refs


# ============================================================================
# 1. A/B/C/D 管线均不抛异常，输出含 #SEMZ1 头
# ============================================================================

@pytest.mark.parametrize("name", sorted(ALL_CORPORA))
@pytest.mark.parametrize("level", ["safe", "full", "max"])
def test_pipeline_runs_all_corpora(name, level):
    result = compress_text(ALL_CORPORA[name], level=level)
    assert result["text"].startswith("#SEMZ1 "), name
    stats = result["stats"]
    assert stats["orig"] > 0
    assert stats["out"] > 0
    assert 0.0 < stats["ratio"]


def test_invalid_level_raises():
    with pytest.raises(CompressError):
        compress_text(CORPUS_A, level="bogus")


def test_parse_formats():
    # 裸 hex 地址 + 空白
    ins = parse_text("401000  mov rax,1\n")
    assert len(ins) == 1 and ins[0].ea == 0x401000
    # 纯指令
    ins = parse_text("mov rax,1\n")
    assert len(ins) == 1 and ins[0].ea is None
    # x64dbg 三列（地址|机器码|反汇编）
    ins = parse_text("00401000 | 55 | push rbp\n")
    assert len(ins) == 1 and ins[0].ea == 0x401000 and ins[0].mnem == "push"


# ============================================================================
# 2. 宏引用/跳转标签闭合（除外部目标外均有定义）
# ============================================================================

@pytest.mark.parametrize("name,level", [("A", "max"), ("B", "max"), ("C", "full"), ("D", "full")])
def test_labels_and_macros_closed(name, level):
    text = compress_text(ALL_CORPORA[name], level=level)["text"]
    assert _referenced_macros(text) <= _defined_macros(text)
    assert _referenced_labels(text) <= _defined_labels(text)


# ============================================================================
# 3. B 必须出现至少 1 个 P 宏且 orig/out >= 1.5
# ============================================================================

def test_corpus_b_macro_folding():
    result = compress_text(CORPUS_B, level="max")
    text = result["text"]
    assert _defined_macros(text), "B 输出必须定义至少 1 个 P 宏"
    assert _referenced_macros(text), "B 输出必须引用至少 1 个 P 宏"
    stats = result["stats"]
    assert stats["orig"] / stats["out"] >= 1.5, stats


# ============================================================================
# 4. C 死代码消除：full 时 #ELIM n>=2；safe 时 elim=0
# ============================================================================

def test_corpus_c_dead_code_eliminated_full():
    result = compress_text(CORPUS_C, level="full")
    stats = result["stats"]
    assert stats["elim"] >= 2, result["text"]
    m = re.search(r"^#ELIM n=(\d+)", result["text"], flags=re.M)
    assert m and int(m.group(1)) >= 2
    elim_texts = [r["text"] for r in result["elim"]]
    # mov rax,1 被 mov rax,2 覆盖；cmp rax,5 的标志被 xor 覆盖
    assert any("mov rax, 1" in t for t in elim_texts), elim_texts
    assert any("cmp rax, 5" in t for t in elim_texts), elim_texts


def test_corpus_c_safe_no_elim():
    result = compress_text(CORPUS_C, level="safe")
    assert result["stats"]["elim"] == 0


# ============================================================================
# 5. 压缩率：A+B 合并语料 ratio <= 60%（字符级，level=max）
# ============================================================================

def test_ratio_ab_merged_max():
    merged = CORPUS_A + CORPUS_B
    result = compress_text(merged, level="max")
    assert result["stats"]["ratio"] <= 60.0, result["stats"]


# ============================================================================
# 6. 幂等/确定性
# ============================================================================

@pytest.mark.parametrize("name,level", [("A", "max"), ("B", "full"), ("C", "max"), ("D", "safe")])
def test_deterministic(name, level):
    t1 = compress_text(ALL_CORPORA[name], level=level)["text"]
    t2 = compress_text(ALL_CORPORA[name], level=level)["text"]
    assert t1 == t2


# ============================================================================
# 7. 头部字典自包含：非 # 行不再出现完整 mov/rax
# ============================================================================

@pytest.mark.parametrize("name", ["A", "B", "C", "D"])
def test_headers_self_contained(name):
    text = compress_text(ALL_CORPORA[name], level="max")["text"]
    for ln in _body_lines(text):
        assert not re.search(r"\bmov\b", ln), ln
        assert not re.search(r"\brax\b", ln), ln


# ============================================================================
# 附加：compress_insns（dict 输入，IDA 侧数据形状）
# ============================================================================

def test_compress_insns_dict_input():
    insns = []
    for line in CORPUS_C.strip().splitlines():
        ea_s, text = line.split(": ", 1)
        insns.append({"ea": int(ea_s, 16), "text": text, "comment": None})
    result = compress_insns(insns, level="full", name="sub_600000")
    assert result["text"].startswith("#SEMZ1 fn=sub_600000 ")
    assert result["stats"]["elim"] >= 2
    assert result["elim"] and set(result["elim"][0]) == {"ea", "text", "reason"}


# ============================================================================
# 任务 1 回归：liveness 不得把无条件 jmp 之后（不可达）的覆盖写当作死亡证明
# ============================================================================

CORPUS_REG_JMP = """\
0x401000: mov eax, 7
0x401005: jmp 0x40100d
0x401007: mov eax, 9
0x40100d: retn
"""

# 变体：条件分支两条可达路径上的赋值，后随不可达覆盖写
CORPUS_REG_COND = """\
0x401000: cmp ecx, 0
0x401003: jz 0x40100f
0x401005: mov eax, 7
0x401007: jmp 0x401013
0x401009: mov eax, 9
0x40100f: mov eax, 3
0x401013: mov ebx, eax
0x401015: retn
"""


@pytest.mark.parametrize("level", ["full", "max", "ultra"])
def test_liveness_unconditional_jmp_unreachable_overwrite(level):
    """无条件 jmp 之后的不可达 mov eax,9 不得误删可达路径上的 mov eax,7。

    §5e 起纯 32 位语料 auto 探测判 x86（裸写=eax 族）；本用例固 arch="x64"
    以保持 x64 路径活性回归覆盖（编码 a4=eax）。"""
    result = compress_text(CORPUS_REG_JMP, level=level, arch="x64")
    text = result["text"]
    assert result["stats"]["elim"] == 0, text
    if level == "ultra":
        assert "m a4,7" in text, text
    else:
        assert "m a!d, 0x7" in text, text  # ret 路径应读到 7


@pytest.mark.parametrize("level", ["full", "max", "ultra"])
def test_liveness_conditional_branch_reachable_def_kept(level):
    """条件分支可达的赋值（mov eax,7 / mov eax,3）保留；不可达覆盖（mov eax,9）删除。

    §5e 起纯 32 位语料 auto 探测判 x86；本用例固 arch="x64"（同上一用例）。"""
    result = compress_text(CORPUS_REG_COND, level=level, arch="x64")
    text = result["text"]
    assert result["stats"]["elim"] == 1, text
    if level == "ultra":
        assert "m a4,7" in text and "m a4,3" in text, text
    else:
        assert "0x7" in text and "0x3" in text, text
        assert any("mov eax, 9" in r["text"] for r in result["elim"]), result["elim"]


# ============================================================================
# ultra 解码一致性（SPEC §5c：测试内嵌同一份全局固定表）
# ============================================================================

from ida_mcp.compress.global_table import (  # noqa: E402
    JCC_CODES,
    MNEMONIC_NAMES,
    REG_NAMES,
    SUFFIX_WIDTH,
)
from ida_mcp.compress.normalize import _REG_CANON  # noqa: E402

# 寄存器码（族码+宽度后缀）→ 规范寄存器名（a→rax, a4→eax, a2→ax, a1→al）
_ULTRA_REG_NAME = {}
for _code, _fam in REG_NAMES.items():
    for _suf, _w in SUFFIX_WIDTH.items():
        _ULTRA_REG_NAME[_code + _suf] = _REG_CANON.get((_fam, _w), _fam)

# 操作数内的符号 token（前面不是数字，避免把 0a1 里的 a1 误当寄存器）
_ULTRA_SYM_RE = re.compile(r"(?<![0-9A-Za-z_.$])[A-Za-z_.$][\w.$]*")
_ULTRA_KREF_RE = re.compile(r"K\d+")
_ULTRA_LREF_RE = re.compile(r"L\d+")
_ULTRA_FUSED_LINE_RE = re.compile(r"g([a-z]+) (L\d+): (.*)")


def _ultra_decode(text: str, reg_names: dict = None) -> dict:
    """把 ultra 正文逐行还原为 (助记符, 操作数) 序列并做结构闭合校验。

    reg_names: 寄存器码 → 规范名表（默认 x64 _ULTRA_REG_NAME；x86 传 _X86_REG_NAME）。

    返回 dict:
        insns       完全展开（含宏展开/融合拆分/多压栈拆分）的 [(mnem, [ops])]
        slots       宏引用按 1 计的正文指令槽数（= 头部 u）
        macro_extra 宏展开多出的指令数 Σ(展开长度-1)
        o/u/e       头部计数
        label_refs/label_defs  分支标签引用/定义
        k_refs/k_defs          #K 引用/定义（正文 + 宏体）
    """
    reg_names = _ULTRA_REG_NAME if reg_names is None else reg_names
    k_defs: dict = {}
    macros: dict = {}
    label_refs: set = set()
    label_defs: set = set()
    k_refs: set = set()
    body: list = []
    head = {}
    for ln in text.splitlines():
        if ln.startswith("#SZ1 "):
            for part in ln[5:].split():
                k, _, v = part.partition("=")
                head[k] = v.rstrip("%")
        elif ln.startswith("#K "):
            for part in ln[3:].split():
                k, _, v = part.partition("=")
                k_defs[k] = v
        elif ln.startswith("#P "):
            name, _, macro_body = ln[3:].partition("=")
            macros[name] = macro_body.split(";")
        elif ln.startswith("#"):
            continue  # #J/#f
        else:
            body.append(ln)

    def dec_op(op: str) -> str:
        def repl(m: re.Match) -> str:
            tok = m.group(0)
            if _ULTRA_KREF_RE.fullmatch(tok):
                k_refs.add(tok)
                return tok
            if _ULTRA_LREF_RE.fullmatch(tok):
                label_refs.add(tok)
                return tok
            if tok in reg_names:
                return reg_names[tok]
            return tok  # 数字 / 标识符 / 透传寄存器（ds、xmm0 等）

        return _ULTRA_SYM_RE.sub(repl, op)

    def dec_plain(ln: str) -> list:
        if " " in ln:
            code, ops_s = ln.split(" ", 1)
            ops = [dec_op(o) for o in ops_s.split(",")]
        else:
            code, ops = ln, []
        if code == "z" and len(ops) == 1:
            return [("xor", [ops[0], ops[0]])]  # 清零习语
        mnem = MNEMONIC_NAMES.get(code, code)  # 未收录助记符原样拼写
        if mnem == "push" and len(ops) > 1:
            return [("push", [o]) for o in ops]  # 多压栈拆分
        if mnem == "test" and len(ops) == 1:
            return [("test", [ops[0], ops[0]])]  # 单操作数 test 习语
        return [(mnem, ops)]

    def dec_line(ln: str) -> list:
        m = _ULTRA_FUSED_LINE_RE.fullmatch(ln)
        if m:
            cc, label, rest = m.groups()
            assert cc in JCC_CODES, ln
            label_refs.add(label)
            inner = dec_plain(rest)
            assert inner and inner[0][0] in ("cmp", "test"), ln
            return inner + [(f"j{cc}", [label])]
        return dec_plain(ln)

    insns: list = []
    slots = 0
    macro_extra = 0
    for ln in body:
        lm = re.fullmatch(r"(L\d+):", ln)
        if lm:
            label_defs.add(lm.group(1))
            continue
        mm = re.fullmatch(r"P\d+", ln)
        if mm:
            name = mm.group(0)
            assert name in macros, f"宏 {name} 未在 #P 定义"
            expanded: list = []
            for ml in macros[name]:
                expanded.extend(dec_line(ml))
            slots += 1  # 宏引用按 1 槽计
            macro_extra += len(expanded) - 1
            insns.extend(expanded)
            continue
        decoded = dec_line(ln)
        slots += len(decoded)  # 融合=2，多压栈=k，普通=1
        insns.extend(decoded)

    return {
        "insns": insns,
        "slots": slots,
        "macro_extra": macro_extra,
        "o": int(head.get("o", 0)),
        "u": int(head.get("u", 0)),
        "e": int(head.get("e", 0)),
        "label_refs": label_refs,
        "label_defs": label_defs,
        "k_refs": k_refs,
        "k_defs": set(k_defs),
    }


def _assert_ultra_consistent(text: str, reg_names: dict = None):
    """ultra 输出通用一致性：头部、无 #MN/#RG、解码闭合。"""
    assert text.startswith("#SZ1 "), text
    for ln in text.splitlines():
        assert not ln.startswith("#MN") and not ln.startswith("#RG"), ln
    dec = _ultra_decode(text, reg_names)
    # 指令数 = 头部 u 值 + 宏展开数
    assert dec["slots"] == dec["u"], (dec["slots"], dec["u"], text)
    assert len(dec["insns"]) == dec["u"] + dec["macro_extra"]
    # 助记符/操作数均可还原
    for mnem, _ops in dec["insns"]:
        assert mnem and isinstance(mnem, str)
    # 所有 g<cc>/j 目标标签闭合
    assert dec["label_refs"] <= dec["label_defs"], (
        dec["label_refs"] - dec["label_defs"], text,
    )
    # #K 引用双向闭合
    assert dec["k_refs"] == dec["k_defs"], (dec["k_refs"], dec["k_defs"], text)
    return dec


@pytest.mark.parametrize("name", sorted(ALL_CORPORA))
def test_ultra_decode_consistency(name):
    text = compress_text(ALL_CORPORA[name], level="ultra")["text"]
    dec = _assert_ultra_consistent(text)
    assert dec["o"] > 0 and dec["u"] > 0


def test_ultra_deterministic():
    t1 = compress_text(CORPUS_A, level="ultra")["text"]
    t2 = compress_text(CORPUS_A, level="ultra")["text"]
    assert t1 == t2


def test_ultra_dce_always_on():
    """ultra 恒按 full 规则 DCE，删除记录丢弃只留 e= 计数。"""
    result = compress_text(CORPUS_C, level="ultra")
    dec = _ultra_decode(result["text"])
    assert result["stats"]["elim"] >= 2
    assert dec["e"] == result["stats"]["elim"]
    assert result["elim"] == []  # 删除记录丢弃
    assert "#-" not in result["text"]


def test_api_tools_default_level_ultra():
    import inspect

    import ida_mcp.api_compress as ac

    for fn in (ac.compress_function, ac.compress_range, ac.compress_text):
        sig = inspect.signature(fn)
        assert sig.parameters["level"].default == "ultra", fn.__name__


# ============================================================================
# 语料 E：真实风格 IDA listing（.text:地址 机器码列 反汇编）
# 标准序言/尾声 + if-else + 循环 + 8 次 API 调用 + 字符串引用 + 4 指令序列 ×3
# ============================================================================

CORPUS_E = """\
.text:00401000 55                       push    rbp
.text:00401001 48 8B EC                 mov     rbp, rsp
.text:00401004 48 83 EC 40              sub     rsp, 40h
.text:00401008 48 8D 0D F1 1F 00 00     lea     rcx, aMaliciousDll ; "mal.dll"
.text:0040100F FF 15 EB 1F 00 00        call    ds:LoadLibraryA
.text:00401015 48 89 45 F8              mov     [rbp-8], rax
.text:00401019 48 83 7D F8 00           cmp     qword ptr [rbp-8], 0
.text:0040101E 75 07                    jnz     short 401027h
.text:00401020 33 C0                    xor     eax, eax
.text:00401022 E9 87 00 00 00           jmp     4010AEh
.text:00401027 48 8D 0D D1 1F 00 00     lea     rcx, aMaliciousDll ; "mal.dll"
.text:0040102E FF 15 C2 1F 00 00        call    ds:GetModuleHandleA
.text:00401034 48 89 45 F8              mov     [rbp-8], rax
.text:00401038 48 8B 45 F8              mov     rax, [rbp-8]
.text:0040103C 48 83 C0 20              add     rax, 20h
.text:00401040 48 89 45 F0              mov     [rbp-10h], rax
.text:00401044 FF 15 A6 1F 00 00        call    ds:ValidatePtr
.text:0040104A 48 8B 45 F8              mov     rax, [rbp-8]
.text:0040104E 48 83 C0 20              add     rax, 20h
.text:00401052 48 89 45 F0              mov     [rbp-10h], rax
.text:00401056 FF 15 A6 1F 00 00        call    ds:ValidatePtr
.text:0040105C 48 8B 45 F8              mov     rax, [rbp-8]
.text:00401060 48 83 C0 20              add     rax, 20h
.text:00401064 48 89 45 F0              mov     [rbp-10h], rax
.text:00401068 FF 15 A6 1F 00 00        call    ds:ValidatePtr
.text:0040106E C7 45 EC 00 00 00 00     mov     dword ptr [rbp-14h], 0
.text:00401075 83 7D EC 0A              cmp     dword ptr [rbp-14h], 0Ah
.text:00401079 7D 0B                    jge     short 40108Ah
.text:0040107B 8B 4D EC                 mov     ecx, [rbp-14h]
.text:0040107E FF 15 8E 1F 00 00        call    ds:LogValue
.text:00401084 83 45 EC 01              add     dword ptr [rbp-14h], 1
.text:00401088 EB E9                    jmp     short 401075h
.text:0040108A 83 7D EC 05              cmp     dword ptr [rbp-14h], 5
.text:0040108E 75 0C                    jnz     short 40109Fh
.text:00401090 48 8D 0D 61 1F 00 00     lea     rcx, aCheckPassed ; "check passed"
.text:00401097 FF 15 5A 1F 00 00        call    ds:MessageLog
.text:0040109D EB 0D                    jmp     short 4010ACh
.text:0040109F 48 8D 0D 51 1F 00 00     lea     rcx, aCheckFailed ; "check failed"
.text:004010A6 FF 15 4A 1F 00 00        call    ds:MessageLog
.text:004010AC 33 C0                    xor     eax, eax
.text:004010AE C9                       leave
.text:004010AF C3                       retn
"""


def test_corpus_e_parse_ida_listing():
    """parse.py 支持 `.text:00401000 55  push rbp` 段名前缀 + 机器码列。"""
    parsed = parse_text(CORPUS_E)
    assert len(parsed) >= 40
    assert parsed[0].ea == 0x401000 and parsed[0].mnem == "push"
    assert parsed[-1].mnem.lower() in ("retn", "ret")


def test_corpus_e_ultra_ratio_le_25pct():
    """SPEC §5c 验收：语料 E ultra ratio ≤ 25%（对 listing 原文）。"""
    result = compress_text(CORPUS_E, level="ultra")
    text = result["text"]
    ratio = len(text) / len(CORPUS_E) * 100
    assert ratio <= 25.0, f"ratio={ratio:.1f}%"
    assert result["stats"]["ratio"] == pytest.approx(ratio, abs=0.15)
    # 标准帧消隐 + 重复 3 次序列进 #P
    assert re.search(r"^#f=40$", text, flags=re.M), text
    assert re.search(r"^#P P0=", text, flags=re.M), text
    dec = _assert_ultra_consistent(text)
    assert dec["o"] == len(parse_text(CORPUS_E))
    assert dec["k_defs"], "语料 E 应产生常量池（重复≥2 常量）"
    assert dec["macro_extra"] > 0, "语料 E 应产生宏展开"


# ============================================================================
# ultra 性能：20000 指令重复模式输入 < 3 秒
# ============================================================================

def _build_repetitive_text(chunks: int = 2000) -> str:
    pattern = [
        "mov rax, [rbp-0x8]",
        "add rax, 0x20",
        "mov [rbp-0x10], rax",
        "mov ecx, [rbp-0x14]",
        "add ecx, 1",
        "mov [rbp-0x14], ecx",
        "cmp ecx, 0xA",
        "mov rdx, rax",
        "xor r8d, r8d",
        "jl {loop}",
    ]
    lines = []
    ea = 0x1000000
    for _ in range(chunks):
        loop_start = ea
        for tmpl in pattern:
            lines.append(f"0x{ea:X}: " + tmpl.format(loop=f"0x{loop_start:X}"))
            ea += 7
    return "\n".join(lines) + "\n"


def test_ultra_performance_20k_insns():
    import time

    text = _build_repetitive_text(2000)  # 20000 指令
    t0 = time.monotonic()
    result = compress_text(text, level="ultra")
    dt = time.monotonic() - t0
    assert result["stats"]["orig"] == 20000
    assert dt < 3.0, f"ultra 20000 指令耗时 {dt:.2f}s"
    _assert_ultra_consistent(result["text"])


# ============================================================================
# §5d ARM64 一等支持
# ============================================================================

# 语料 F：ARM64 IDA listing（段名:16 位 hex 地址 + 机器码列 + 大写反汇编 + #imm）
# 46 指令：stp 序言、adrp+add 字符串 ×2、cmp+b.hs/b.eq 融合、cbz 循环、
# ldr/str/ldrb、bl 调用 ×3（含同址 ×2）、ldp 尾声；4+1 指令序列重复 ×2（成宏）
_F_SEED = [
    ("STP X29, X30, [SP,#-0x50]!", "FD 7B BB A9", None),
    ("MOV X29, SP", "FD 43 00 91", None),
    ("SUB SP, SP, #0x20", "FF 83 00 D1", None),
    ("STR W0, [SP,#0x2C]", "E0 2F 00 B9", None),
    ("ADRP X8, #0x402000", "08 00 00 B0", None),
    ("ADD X8, X8, #0x48", "08 21 01 91", None),
    ("STR X8, [SP,#0x20]", "E8 13 00 F9", None),
    ("LDR X8, [SP,#0x20]", "E8 13 40 F9", None),
    ("LDRB W9, [X8]", "09 01 40 39", None),
    ("CBZ W9, {fail}", "69 02 00 B4", None),
    ("MOV W10, #0", "4A 01 80 52", None),
    ("STR W10, [SP,#0x3C]", "EA 3F 00 B9", None),
    ("LDR W10, [SP,#0x3C]", "EA 3F 40 B9", "loop"),
    ("CMP W10, #0x10", "5F 41 00 F1", None),
    ("B.HS {chk}", "4A 01 00 54", None),
    ("LDR X8, [SP,#0x20]", "E8 13 40 F9", None),
    ("LDR W10, [SP,#0x3C]", "EA 3F 40 B9", None),
    ("ADD X8, X8, X10", "08 01 0A 8B", None),
    ("LDRB W9, [X8]", "09 01 40 39", None),
    ("CBZ W9, {chk}", "C9 00 00 B4", None),
    ("LDR W10, [SP,#0x3C]", "EA 3F 40 B9", None),
    ("ADD W10, W10, #1", "4A 05 00 11", None),
    ("STR W10, [SP,#0x3C]", "EA 3F 00 B9", None),
    ("B {loop}", "EC FF FF 17", None),
    ("LDR W10, [SP,#0x3C]", "EA 3F 40 B9", "chk"),
    ("CMP W10, #0", "5F 01 00 F1", None),
    ("B.EQ {fail}", "60 01 00 54", None),
    ("ADRP X8, #0x403000", "08 00 00 B0", None),
    ("ADD X8, X8, #0x90", "08 41 02 91", None),
    ("LDR X0, [X8]", "00 01 40 F9", None),
    ("BL 0x450000", "00 00 03 94", None),
    ("LDR X8, [SP,#0x28]", "E8 17 40 F9", None),
    ("ADD X8, X8, #0x20", "08 81 00 91", None),
    ("STR X8, [SP,#0x28]", "E8 17 00 F9", None),
    ("LDR X0, [SP,#0x28]", "E0 17 40 F9", None),
    ("BL 0x450000", "00 00 03 94", None),
    ("LDR X8, [SP,#0x28]", "E8 17 40 F9", None),
    ("ADD X8, X8, #0x20", "08 81 00 91", None),
    ("STR X8, [SP,#0x28]", "E8 17 00 F9", None),
    ("LDR X0, [SP,#0x28]", "E0 17 40 F9", None),
    ("BL 0x450018", "06 00 03 94", None),
    ("MOV W0, #1", "20 00 80 52", None),
    ("B {done}", "02 00 00 14", None),
    ("MOV W0, #0", "00 00 80 52", "fail"),
    ("LDP X29, X30, [SP],#0x50", "FD 7B C5 A8", "done"),
    ("RET", "C0 03 5F D6", None),
]
_F_LABELS = {}
for _i, (_t, _mc, _lab) in enumerate(_F_SEED):
    if _lab:
        _F_LABELS[_lab] = 0x401000 + 4 * _i
CORPUS_F = "\n".join(
    f".text:{0x401000 + 4 * _i:016X} {_mc}  "
    + _t.format(**{k: f"0x{v:X}" for k, v in _F_LABELS.items()})
    for _i, (_t, _mc, _lab) in enumerate(_F_SEED)
) + "\n"


def test_corpus_f_parse_arm64_listing():
    """parse.py 支持 `.text:0000000000401000 FD 7B BB A9  STP X29, X30, [SP,#-0x50]!`。"""
    parsed = parse_text(CORPUS_F)
    assert len(parsed) >= 40
    assert parsed[0].ea == 0x401000
    assert parsed[0].mnem == "STP"
    assert parsed[0].ops == ["X29", "X30", "[SP,#-0x50]!"]
    assert parsed[-1].mnem == "RET"
    # `#imm` / 后索引 操作数原样保留
    assert any("#-0x50" in op for ins in parsed for op in ins.ops)
    assert any(op == "#0x50" for ins in parsed for op in ins.ops)


# ----------------------------------------------------------------------------
# ARM64 ultra 解码一致性（SPEC §5d：内嵌同一份全局固定表）
# ----------------------------------------------------------------------------

from ida_mcp.compress.global_table import (  # noqa: E402
    ARM64_COND_CODES,
    ARM64_MNEMONIC_NAMES,
    ARM64_REG_NAMES,
)

# 寄存器码 → 规范名（含 w 前缀 32 位视图：wb=w1, wS=wsp, wZ=wzr）
_A64_REG_NAME = {}
for _code, _name in ARM64_REG_NAMES.items():
    _A64_REG_NAME[_code] = _name
    _A64_REG_NAME["w" + _code] = {"S": "wsp", "Z": "wzr", "P": "pc"}.get(
        _code, "w" + _name[1:]
    )

_A64_SYM_RE = re.compile(r"(?<![0-9A-Za-z_.$])[A-Za-z_.$][\w.$]*")
_A64_KREF_RE = re.compile(r"K\d+")
_A64_LREF_RE = re.compile(r"L\d+")
_A64_FUSED_LINE_RE = re.compile(r"g([a-z]+) (L\d+): (.*)")
_A64_JCC_LINE_RE = re.compile(r"j([a-z]+)")
_A64_SHIFT_TAIL_RE = re.compile(r":[lrRaRuxUX]\d*$")


def _arm64_ultra_decode(text: str) -> dict:
    """ARM64 ultra 正文解码 + 结构闭合校验（同 x64 _ultra_decode 检查项）。

    返回 {insns, slots, macro_extra, o/u/e, label_refs/defs, k_refs/defs, p_refs/defs}
    """
    k_defs: dict = {}
    macros: dict = {}
    label_refs: set = set()
    label_defs: set = set()
    k_refs: set = set()
    p_refs: set = set()
    body: list = []
    head: dict = {}
    for ln in text.splitlines():
        if ln.startswith("#SZ1 "):
            for part in ln[5:].split():
                k, _, v = part.partition("=")
                head[k] = v.rstrip("%")
        elif ln.startswith("#K "):
            for part in ln[3:].split():
                k, _, v = part.partition("=")
                k_defs[k] = v
        elif ln.startswith("#P "):
            name, _, macro_body = ln[3:].partition("=")
            macros[name] = macro_body.split(";")
        elif ln.startswith("#"):
            continue  # #J/#f
        else:
            body.append(ln)

    def dec_op(op: str) -> str:
        op = _A64_SHIFT_TAIL_RE.sub("", op)  # 剥离移位/扩展后缀 :l3/:u/:u2
        def repl(m: re.Match) -> str:
            tok = m.group(0)
            if _A64_KREF_RE.fullmatch(tok):
                k_refs.add(tok)
                return tok
            if _A64_LREF_RE.fullmatch(tok):
                label_refs.add(tok)
                return tok
            if tok in _A64_REG_NAME:
                return _A64_REG_NAME[tok]
            return tok  # 数字 / 标识符 / SIMD 透传

        return _A64_SYM_RE.sub(repl, op)

    def dec_plain(ln: str) -> list:
        if " " in ln:
            code, ops_s = ln.split(" ", 1)
            ops = [dec_op(o) for o in ops_s.split(",")]
        else:
            code, ops = ln, []
        if code == "z" and len(ops) == 1:
            return [("mov", [ops[0], "#0"])]  # 清零习语（mov xd,#0 / eor xd,xd,xd）
        jm = _A64_JCC_LINE_RE.fullmatch(code)
        if jm and jm.group(1) in ARM64_COND_CODES:
            return [(f"b.{jm.group(1)}", ops)]  # 独立 b.cond
        mnem = ARM64_MNEMONIC_NAMES.get(code, code)  # cbz/tbz/br/blr/svc 等原样拼写
        return [(mnem, ops)]

    def dec_line(ln: str) -> list:
        m = _A64_FUSED_LINE_RE.fullmatch(ln)
        if m:
            cc, label, rest = m.groups()
            assert cc in ARM64_COND_CODES, ln
            label_refs.add(label)
            inner = dec_plain(rest)
            assert inner and inner[0][0] in ("cmp", "tst"), ln
            return inner + [(f"b.{cc}", [label])]
        return dec_plain(ln)

    insns: list = []
    slots = 0
    macro_extra = 0
    for ln in body:
        lm = re.fullmatch(r"(L\d+):", ln)
        if lm:
            label_defs.add(lm.group(1))
            continue
        mm = re.fullmatch(r"P\d+", ln)
        if mm:
            name = mm.group(0)
            assert name in macros, f"宏 {name} 未在 #P 定义"
            p_refs.add(name)
            expanded: list = []
            for ml in macros[name]:
                expanded.extend(dec_line(ml))
            slots += 1  # 宏引用按 1 槽计
            macro_extra += len(expanded) - 1
            insns.extend(expanded)
            continue
        decoded = dec_line(ln)
        slots += len(decoded)  # g<cc> 融合=2，普通=1
        insns.extend(decoded)

    return {
        "insns": insns,
        "slots": slots,
        "macro_extra": macro_extra,
        "o": int(head.get("o", 0)),
        "u": int(head.get("u", 0)),
        "e": int(head.get("e", 0)),
        "label_refs": label_refs,
        "label_defs": label_defs,
        "k_refs": k_refs,
        "k_defs": set(k_defs),
        "p_refs": p_refs,
        "p_defs": set(macros),
    }


def _assert_arm64_ultra_consistent(text: str):
    """ARM64 ultra 一致性：头部、arch=arm64、无 #MN/#RG、解码闭合。"""
    assert text.startswith("#SZ1 "), text
    assert " arch=arm64 " in text, text
    for ln in text.splitlines():
        assert not ln.startswith("#MN") and not ln.startswith("#RG"), ln
    dec = _arm64_ultra_decode(text)
    # 指令数核对：槽数 = 头部 u；展开数 = u + 宏展开差
    assert dec["slots"] == dec["u"], (dec["slots"], dec["u"], text)
    assert len(dec["insns"]) == dec["u"] + dec["macro_extra"]
    for mnem, _ops in dec["insns"]:
        assert mnem and isinstance(mnem, str)
    # 标签闭合
    assert dec["label_refs"] <= dec["label_defs"], (
        dec["label_refs"] - dec["label_defs"], text,
    )
    # #K / #P 双向闭合
    assert dec["k_refs"] == dec["k_defs"], (dec["k_refs"], dec["k_defs"], text)
    assert dec["p_refs"] == dec["p_defs"], (dec["p_refs"], dec["p_defs"], text)
    return dec


def test_corpus_f_ultra_ratio_le_25pct():
    """SPEC §5d 验收：语料 F ultra ratio ≤ 25%（对 listing 原文），含 #f=，无 #MN/#RG。"""
    result = compress_text(CORPUS_F, level="ultra")
    text = result["text"]
    ratio = len(text) / len(CORPUS_F) * 100
    assert ratio <= 25.0, f"ratio={ratio:.1f}%"
    assert result["stats"]["ratio"] == pytest.approx(ratio, abs=0.15)
    # 标准帧消隐（stp 0x50 + sub 0x20 = 0x70）
    assert re.search(r"^#f=70$", text, flags=re.M), text
    # cmp+b.hs → b.cs 归一融合；cmp+b.eq 融合；cbz 原生保持
    assert re.search(r"^gcs L\d+: f ", text, flags=re.M), text
    assert re.search(r"^geq L\d+: f ", text, flags=re.M), text
    assert re.search(r"^cbz ", text, flags=re.M), text
    dec = _assert_arm64_ultra_consistent(text)
    assert dec["o"] == len(parse_text(CORPUS_F))
    assert dec["p_defs"], "语料 F 应产生序列宏（重复×2 的 5 指令块）"
    assert dec["macro_extra"] > 0


# ----------------------------------------------------------------------------
# §5d ARM64 liveness 用例
# ----------------------------------------------------------------------------

def test_arm64_liveness_w_write_kills_x_family():
    """写 w0 = 写整个 x0 族：mov x0,#7 被 mov w0,#9 杀死。"""
    result = compress_text("mov x0,#7\nmov w0,#9\nret", level="full", arch="arm64")
    assert result["stats"]["elim"] == 1, result["text"]
    assert any("mov x0" in e["text"] for e in result["elim"]), result["elim"]


def test_arm64_liveness_arg_kept_before_bl():
    """mov x0,#5; bl foo：bl 保守读 x0-x7，mov 保留。"""
    result = compress_text("mov x0,#5\nbl 0x450000\nret", level="full", arch="arm64")
    assert result["stats"]["elim"] == 0, result["text"]


def test_arm64_liveness_overwrite_eliminated():
    """mov x9,#1; mov x9,#2; ret：删第一条。"""
    result = compress_text("mov x9,#1\nmov x9,#2\nret", level="full", arch="arm64")
    assert result["stats"]["elim"] == 1, result["text"]
    assert any("mov x9,#1" in e["text"] for e in result["elim"]), result["elim"]


def test_arm64_liveness_mov_kept_flags_alive():
    """cmp x0,#0; mov x1,x2; b.eq：mov 不写标志，cmp 标志活到 b.eq，二者均保留。"""
    result = compress_text("cmp x0,#0\nmov x1,x2\nb.eq 0x401020", level="ultra", arch="arm64")
    assert result["stats"]["elim"] == 0, result["text"]
    assert "f a,0" in result["text"] and "m b,c" in result["text"], result["text"]
    assert re.search(r"^jeq ", result["text"], flags=re.M), result["text"]


def test_arm64_liveness_stp_writeback_kept():
    """stp x29,x30,[sp,#-0x50]! 的 sp 写回不被误删（level=full，无帧消隐）。"""
    text_in = (
        "stp x29,x30,[sp,#-0x50]!\nmov x29,sp\nsub sp,sp,#0x20\n"
        "mov x0,#1\nadd sp,sp,#0x20\nldp x29,x30,[sp],#0x50\nret"
    )
    result = compress_text(text_in, level="full", arch="arm64")
    assert "[S-0x50]!" in result["text"], result["text"]
    assert not any("stp" in e["text"] for e in result["elim"]), result["elim"]


# ----------------------------------------------------------------------------
# §5d auto 探测 / 显式覆盖 / 确定性 / 空输入
# ----------------------------------------------------------------------------

_ARM64_AUTO_SAMPLES = [
    "STP X29, X30, [SP,#-0x50]!\nMOV X29, SP\nLDP X29, X30, [SP],#0x50\nRET",
    "adrp x8, #0x402000\nadd x8, x8, #0x40\ncbz w0, 0x401080\nldr x0, [x8]\nret",
    "cmp x0, #0x10\nb.eq 0x401020\nmovz w0, #0x1234\nmovk x0, #5, lsl #16\nsvc #0",
]
_X64_AUTO_SAMPLES = [
    "push rbp\nmov rbp, rsp\nsub rsp, 0x20\npop rbp\nretn",
    "mov eax, dword ptr [rbp-4]\ncmp eax, 0xA\njl 0x401022\nretn",
    "00401000 | 55 | push rbp\n00401001 | 48:8BEC | mov rbp, rsp\n00401004 | C3 | ret",
]


def test_auto_detect_arm64_samples():
    from ida_mcp.compress.parse import detect_arch

    for sample in _ARM64_AUTO_SAMPLES:
        assert detect_arch(parse_text(sample)) == "arm64", sample
        assert " arch=arm64 " in compress_text(sample, level="ultra")["text"]


def test_auto_detect_x64_samples():
    from ida_mcp.compress.parse import detect_arch

    for sample in _X64_AUTO_SAMPLES:
        assert detect_arch(parse_text(sample)) is None, sample
    assert " arch=arm64 " not in compress_text(CORPUS_A, level="ultra")["text"]


def test_arch_explicit_override():
    """显式 arch 覆盖 auto 探测。"""
    r_x64 = compress_text(CORPUS_F, level="ultra", arch="x64")
    assert " arch=arm64 " not in r_x64["text"]
    r_arm = compress_text(CORPUS_A, level="ultra", arch="arm64")
    assert " arch=arm64 " in r_arm["text"]


def test_arm64_ultra_deterministic():
    t1 = compress_text(CORPUS_F, level="ultra")["text"]
    t2 = compress_text(CORPUS_F, level="ultra")["text"]
    assert t1 == t2


def test_arm64_empty_input_raises():
    with pytest.raises(CompressError):
        compress_text("  \n ", level="ultra", arch="arm64")
    with pytest.raises(CompressError):
        compress_insns([], level="ultra", arch="arm64")


def test_arm64_movz_movk_shift_encoding():
    """SPEC §5d：movz/movk `z a,1234` / `k a,5:l16`；移位后缀 :l3。"""
    result = compress_text(
        "movz w0, #0x1234\nmovk x0, #5, lsl #16\nadd x1, x2, x3, lsl #3\nret",
        level="ultra", arch="arm64",
    )
    text = result["text"]
    assert "z wa,1234" in text, text
    assert "k a,5:l16" in text, text
    assert "add b,c,d:l3" in text, text
    _assert_arm64_ultra_consistent(text)


def test_arm64_memory_forms_encoding():
    """SPEC §5d：`[S+40]` / 预索引 `[S-50]!` / 后索引 `p D,E,[S]+50`。"""
    result = compress_text(
        "stp x29,x30,[sp,#-0x40]!\nldr x0,[sp,#0x40]\nstr w1,[sp,#0x10]\n"
        "ldp x29,x30,[sp],#0x40\nret",
        level="full", arch="arm64",
    )
    body = result["text"]
    assert "[S-0x40]!" in body and "[S+0x40]" in body and "[S], 0x40" in body, body
    r2 = compress_text(
        "stp x29,x30,[sp,#-0x40]!\nldr x0,[sp,#0x40]\nldp x29,x30,[sp],#0x40\nret",
        level="ultra", arch="arm64",
    )
    assert "q D,E,[S-40]!" in r2["text"] or "#f=" in r2["text"], r2["text"]


def test_api_tools_have_arch_param():
    import inspect

    import ida_mcp.api_compress as ac

    for fn in (ac.compress_function, ac.compress_range, ac.compress_text):
        sig = inspect.signature(fn)
        assert sig.parameters["arch"].default == "auto", fn.__name__


# ============================================================================
# §5e x86（32 位）支持
# ============================================================================

# 语料 G：x86 IDA listing（.text:8 位 hex 地址 + 机器码列 + 反汇编）
# 38 指令：push ebp 序言、fs:[30] PEB 访问、循环（cmp+jl 融合）、
# call dword ptr [iat] ×2、绝对内存 [405030h] 引用 ×5（重复≥2 池化）、
# 7 指令序列 ×2（成宏）、leave;retn 尾声
CORPUS_G = """\
.text:00401000 55                       push    ebp
.text:00401001 8B EC                    mov     ebp, esp
.text:00401003 83 EC 1C                 sub     esp, 1Ch
.text:00401006 64 A1 30 00 00 00        mov     eax, large dword ptr fs:30h
.text:0040100C 8B 40 0C                 mov     eax, [eax+0Ch]
.text:0040100F 89 45 FC                 mov     [ebp-4], eax
.text:00401012 8B 45 FC                 mov     eax, [ebp-4]
.text:00401015 8B 40 30                 mov     eax, [eax+30h]
.text:00401018 89 45 F0                 mov     [ebp-10h], eax
.text:0040101B C7 45 F8 00 00 00 00     mov     dword ptr [ebp-8], 0
.text:00401022 C7 45 F4 00 00 00 00     mov     dword ptr [ebp-0Ch], 0
.text:00401029 EB 0A                    jmp     short 401035h
.text:0040102B 8B 45 F4                 mov     eax, [ebp-0Ch]
.text:0040102E 01 45 F8                 add     [ebp-8], eax
.text:00401031 83 45 F4 01              add     dword ptr [ebp-0Ch], 1
.text:00401035 83 7D F4 0A              cmp     dword ptr [ebp-0Ch], 0Ah
.text:00401039 7C F0                    jl      short 40102Bh
.text:0040103B 8B 45 F8                 mov     eax, [ebp-8]
.text:0040103E 8B 0D 30 50 40 00        mov     ecx, [405030h]
.text:00401044 03 C8                    add     ecx, eax
.text:00401046 89 0D 30 50 40 00        mov     [405030h], ecx
.text:0040104C 50                       push    eax
.text:0040104D FF 15 1C 20 40 00        call    dword ptr [40201Ch]
.text:00401053 83 C4 04                 add     esp, 4
.text:00401056 8B 45 F8                 mov     eax, [ebp-8]
.text:00401059 8B 0D 30 50 40 00        mov     ecx, [405030h]
.text:0040105F 03 C8                    add     ecx, eax
.text:00401061 89 0D 30 50 40 00        mov     [405030h], ecx
.text:00401067 50                       push    eax
.text:00401068 FF 15 1C 20 40 00        call    dword ptr [40201Ch]
.text:0040106E 83 C4 04                 add     esp, 4
.text:00401071 83 3D 30 50 40 00 00     cmp     dword ptr [405030h], 0
.text:00401078 75 07                    jnz     short 401081h
.text:0040107A B8 01 00 00 00           mov     eax, 1
.text:0040107F EB 02                    jmp     short 401083h
.text:00401081 33 C0                    xor     eax, eax
.text:00401083 C9                       leave
.text:00401084 C3                       retn
"""


def test_corpus_g_parse_x86_listing():
    """parse.py 支持 x86 `.text:00401000 55  push ebp` 段名前缀 + 机器码列。"""
    parsed = parse_text(CORPUS_G)
    assert len(parsed) >= 36
    assert parsed[0].ea == 0x401000 and parsed[0].mnem == "push"
    assert parsed[0].ops == ["ebp"]
    assert parsed[-1].mnem.lower() in ("retn", "ret")
    # fs 段前缀操作数原样进入操作数列
    assert any("fs:30h" in op for ins in parsed for op in ins.ops)


# ----------------------------------------------------------------------------
# x86 ultra 解码一致性（SPEC §5e：内嵌同一份全局固定表，裸写=eax 族）
# ----------------------------------------------------------------------------

from ida_mcp.compress.global_table import (  # noqa: E402
    X86_REG_CODES,
    X86_WIDTH_SUFFIX,
)

# 寄存器码（族码+宽度后缀）→ 规范寄存器名（a→eax, a2→ax, a1→al, g→esp, h→ebp, R→eip）
_X86_REG_NAME = {}
for _fam, _code in X86_REG_CODES.items():
    for _w, _suf in X86_WIDTH_SUFFIX.items():
        _X86_REG_NAME[_code + _suf] = _REG_CANON.get((_fam, _w), _fam)


def _x86_ultra_decode(text: str) -> dict:
    return _ultra_decode(text, _X86_REG_NAME)


def _assert_x86_ultra_consistent(text: str):
    """x86 ultra 一致性：头部 arch=x86、无 #MN/#RG、解码闭合（同 x64 检查项）。"""
    assert " arch=x86 " in text, text
    return _assert_ultra_consistent(text, _X86_REG_NAME)


def test_corpus_g_ultra_ratio_le_25pct():
    """SPEC §5e 验收：语料 G ultra ratio ≤ 25%（对 listing 原文）、#f= 命中、无 #MN/#RG、宏出现。"""
    result = compress_text(CORPUS_G, level="ultra")
    text = result["text"]
    ratio = len(text) / len(CORPUS_G) * 100
    assert ratio <= 25.0, f"ratio={ratio:.1f}%"
    assert result["stats"]["ratio"] == pytest.approx(ratio, abs=0.15)
    # 标准帧消隐（sub esp,1Ch）
    assert re.search(r"^#f=1c$", text, flags=re.M), text
    # 重复×2 的 7 指令序列成宏且被引用
    assert re.search(r"^#P P0=", text, flags=re.M), text
    assert re.search(r"^P0$", text, flags=re.M), text
    dec = _assert_x86_ultra_consistent(text)
    assert dec["o"] == len(parse_text(CORPUS_G))
    assert dec["macro_extra"] > 0


def test_corpus_g_ultra_forms():
    """语料 G 形态断言：段前缀 [fs+30]、绝对内存池化 [K0]、IAT call、cmp+jl 融合、清零习语。"""
    text = compress_text(CORPUS_G, level="ultra")["text"]
    assert "m a,[fs+30]" in text, text           # mov eax, large dword ptr fs:30h
    assert re.search(r"^#K K0=0x405030$", text, flags=re.M), text  # 重复≥2 绝对内存入池
    assert "[K0]" in text, text
    assert re.search(r"^c \[40201c\]$", text, flags=re.M) or "c [40201c]" in text, text  # call dword ptr [iat]
    assert re.search(r"^gl L\d+: k ", text, flags=re.M), text      # 循环 cmp+jl 融合
    assert re.search(r"^z a$", text, flags=re.M), text             # xor eax,eax 习语
    # x86 默认 dword 无宽度后缀（`]4` 后缀不出现）
    assert "m [h-8],0" in text, text
    assert "]4" not in text, text


def test_x86_ultra_decode_bare_reg_is_eax_family():
    """x86 解码一致性：裸写=eax 族（a→eax, g→esp, h→ebp），绝不还原出 64 位名。"""
    text = compress_text(CORPUS_G, level="ultra")["text"]
    dec = _x86_ultra_decode(text)
    flat_ops = [op for _m, ops in dec["insns"] for op in ops]
    assert any(mnem == "mov" and ops[:1] == ["eax"] for mnem, ops in dec["insns"])
    for bad in ("rax", "rbx", "rcx", "rdx", "rsp", "rbp"):
        assert bad not in flat_ops, bad
    # esp/ebp 族正确还原（帧消隐后正文里 h 仅作内存基址出现 → ebp）
    assert any("[ebp-8]" in op for op in flat_ops), flat_ops


# ----------------------------------------------------------------------------
# §5e x86 liveness 用例
# ----------------------------------------------------------------------------

def test_x86_liveness_overwrite_eliminated():
    """mov eax,1; mov eax,2; ret：删第一条。"""
    result = compress_text("mov eax,1\nmov eax,2\nret", level="full", arch="x86")
    assert result["stats"]["elim"] == 1, result["text"]
    assert any("mov eax,1" in e["text"] for e in result["elim"]), result["elim"]


def test_x86_liveness_arg_kept_before_call():
    """mov eax,5; call dword ptr [iat]：call 保守屏障，mov 保留。"""
    result = compress_text(
        "mov eax,5\ncall dword ptr [40201Ch]\nretn", level="full", arch="x86"
    )
    assert result["stats"]["elim"] == 0, result["text"]
    ultra = compress_text(
        "mov eax,5\ncall dword ptr [40201Ch]\nretn", level="ultra", arch="x86"
    )
    assert "m a,5" in ultra["text"], ultra["text"]


def test_x86_liveness_prologue_writeback_kept():
    """push ebp 序言的 esp/ebp 写回不被误删（level=full，无帧消隐）。"""
    text_in = (
        "push ebp\nmov ebp,esp\nsub esp,0x1C\nmov eax,[ebp-4]\n"
        "mov esp,ebp\npop ebp\nretn"
    )
    result = compress_text(text_in, level="full", arch="x86")
    elim_texts = [e["text"] for e in result["elim"]]
    assert not any("push ebp" in t for t in elim_texts), elim_texts
    assert not any("mov ebp" in t for t in elim_texts), elim_texts
    assert not any("sub esp" in t for t in elim_texts), elim_texts


# ----------------------------------------------------------------------------
# §5e auto 探测矩阵：x86/x64/arm64 各 ≥3 样本（含既有语料回归）
# ----------------------------------------------------------------------------

_X86_AUTO_SAMPLES = [
    "mov eax, dword ptr [ebp-4]\nadd eax, 1\nretn",
    "push ebp\nmov ebp, esp\nsub esp, 0x10\nleave\nretn",
    "mov ecx, [405030h]\nadd ecx, eax\nmov [405030h], ecx\nretn",
]


def test_auto_detect_x86_samples():
    from ida_mcp.compress.parse import detect_arch

    for sample in _X86_AUTO_SAMPLES:
        assert detect_arch(parse_text(sample)) == "x86", sample
        assert " arch=x86 " in compress_text(sample, level="ultra")["text"]
    assert detect_arch(parse_text(CORPUS_G)) == "x86"


def test_auto_detect_x64_regression():
    """既有 x64 语料（含 x64dbg trace）仍判 x64（detect None = x64 路径）。"""
    from ida_mcp.compress.parse import detect_arch

    for sample in _X64_AUTO_SAMPLES:
        assert detect_arch(parse_text(sample)) is None, sample
    for corpus in (CORPUS_A, CORPUS_B, CORPUS_D, CORPUS_E):
        assert detect_arch(parse_text(corpus)) is None
        assert " arch=x64 " in compress_text(corpus, level="ultra")["text"]


def test_auto_detect_arm64_regression():
    from ida_mcp.compress.parse import detect_arch

    for sample in _ARM64_AUTO_SAMPLES:
        assert detect_arch(parse_text(sample)) == "arm64", sample
    assert detect_arch(parse_text(CORPUS_F)) == "arm64"
    assert " arch=arm64 " in compress_text(CORPUS_F, level="ultra")["text"]


# ----------------------------------------------------------------------------
# §5e 编码形态：retn N / 绝对内存池化 / 段前缀 / 帧变体 / 多压栈 / 宽度后缀
# ----------------------------------------------------------------------------

def test_x86_retn_n_encoding():
    """retn N（stdcall 被调方清理）→ `r N`（操作数保留）。"""
    result = compress_text("mov eax, 1\nretn 0x10", level="ultra", arch="x86")
    assert re.search(r"^r 10$", result["text"], flags=re.M), result["text"]


def test_x86_retn_n_frame_elision():
    """stdcall 标准帧：leave;retn 0x10 → #f=8 命中且 `r 10` 保留。"""
    result = compress_text(
        "push ebp\nmov ebp,esp\nsub esp,8\nmov eax,[ebp+8]\nleave\nretn 0x10",
        level="ultra", arch="x86",
    )
    text = result["text"]
    assert re.search(r"^#f=8$", text, flags=re.M), text
    assert re.search(r"^r 10$", text, flags=re.M), text
    _assert_x86_ultra_consistent(text)


def test_x86_frame_elision_mov_pop_variant():
    """mov esp,ebp; pop ebp; ret 尾声变体 → #f=20。"""
    result = compress_text(
        "push ebp\nmov ebp,esp\nsub esp,0x20\nmov eax,1\nmov esp,ebp\npop ebp\nretn",
        level="ultra", arch="x86",
    )
    assert re.search(r"^#f=20$", result["text"], flags=re.M), result["text"]


def test_x86_abs_mem_pooling():
    """绝对内存 `[405030]`：重复≥2 池化为 `[K0]`，单次内联。"""
    result = compress_text(
        "mov eax,[0x405030]\nadd eax,[0x405030]\nmov [0x405030],eax\nretn",
        level="ultra", arch="x86",
    )
    text = result["text"]
    assert re.search(r"^#K K0=0x405030$", text, flags=re.M), text
    assert "m a,[K0]" in text and "m [K0],a" in text, text
    # 单次出现的绝对内存内联
    single = compress_text("mov eax,[0x405040]\nretn", level="ultra", arch="x86")
    assert "m a,[405040]" in single["text"], single["text"]
    assert "#K " not in single["text"], single["text"]


def test_x86_segment_prefix_form():
    """段前缀内存保持 `[fs+30]` 形态。"""
    result = compress_text(
        "mov eax, large dword ptr fs:30h\nretn", level="ultra", arch="x86"
    )
    assert "m a,[fs+30]" in result["text"], result["text"]
    bracket = compress_text(
        "mov eax, dword ptr fs:[30h]\nretn", level="ultra", arch="x86"
    )
    assert "m a,[fs+30]" in bracket["text"], bracket["text"]


def test_x86_mem_width_suffixes():
    """x86 内存默认 dword 无后缀；非 dword 用 8/4/2/1 后缀。"""
    result = compress_text(
        "mov dword ptr [ebp-4], 0\nmov byte ptr [ebp-1], 0\n"
        "mov word ptr [ebp-2], 0\nmov qword ptr [ebp-8], 0\nretn",
        level="ultra", arch="x86",
    )
    text = result["text"]
    assert "m [h-4],0" in text, text    # dword：无后缀
    assert "m [h-1]1,0" in text, text   # byte → 1
    assert "m [h-2]2,0" in text, text   # word → 2
    assert "m [h-8]8,0" in text, text   # qword → 8


def test_x86_multi_push_and_high_byte():
    """多压栈合并与 ah..dh 原样拼写。"""
    result = compress_text(
        "push eax\npush ebx\npush ebp\ncall dword ptr [40201Ch]\nretn",
        level="ultra", arch="x86",
    )
    assert re.search(r"^p a,b,h$", result["text"], flags=re.M), result["text"]
    hb = compress_text("mov ah, 1\nmov dh, 2\nretn", level="ultra", arch="x86")
    assert "m ah,1" in hb["text"] and "m dh,2" in hb["text"], hb["text"]


def test_x86_subregister_encoding():
    """x86 宽度后缀：ax→a2、al→a1（各用独立族，避免族粒度 DCE 覆盖）。"""
    result = compress_text(
        "mov ax, 1\nmov bl, 2\nmov cx, 3\nmov dl, 4\nretn",
        level="ultra", arch="x86",
    )
    text = result["text"]
    for form in ("m a2,1", "m b1,2", "m c2,3", "m d1,4"):
        assert form in text, (form, text)


# ----------------------------------------------------------------------------
# §5e 其它级别 / 确定性 / 空输入
# ----------------------------------------------------------------------------

@pytest.mark.parametrize("level", ["safe", "full", "max"])
def test_x86_other_levels_run(level):
    """x86 在 safe/full/max 级别复用 x64 路径：不抛异常、arch=x86、#SEMZ1 头。"""
    result = compress_text(CORPUS_G, level=level)
    assert result["text"].startswith("#SEMZ1 "), result["text"]
    assert " arch=x86 " in result["text"], result["text"]
    assert result["stats"]["orig"] == len(parse_text(CORPUS_G))


def test_x86_ultra_deterministic():
    t1 = compress_text(CORPUS_G, level="ultra")["text"]
    t2 = compress_text(CORPUS_G, level="ultra")["text"]
    assert t1 == t2


def test_x86_empty_input_raises():
    with pytest.raises(CompressError):
        compress_text("  \n ", level="ultra", arch="x86")
    with pytest.raises(CompressError):
        compress_insns([], level="ultra", arch="x86")


# ============================================================================
# api_compress.compress_text 输出整形（纯 Python，无需 IDA）
# ============================================================================

from ida_mcp.api_compress import compress_text as _api_compress_text  # noqa: E402


class TestOutputShaping:
    """compress 包装层：直接读 / 分级 / 落盘 三种输出模式。"""

    def test_inline_default_stats_before_compressed(self):
        r = _api_compress_text(CORPUS_A, level="ultra", arch="x64")
        assert "compressed" in r and r["compressed"]
        assert r["stats"]["orig"] > 0
        assert list(r).index("stats") < list(r).index("compressed")

    def test_line_paging(self):
        full = _api_compress_text(CORPUS_A, level="ultra", arch="x64")
        lines = full["compressed"].splitlines()
        p1 = _api_compress_text(CORPUS_A, level="ultra", arch="x64", line_limit=3)
        assert p1["line_total"] == len(lines)
        assert p1["line_offset"] == 0
        assert p1["compressed"].splitlines() == lines[:3]
        p2 = _api_compress_text(
            CORPUS_A, level="ultra", arch="x64", line_offset=3, line_limit=2
        )
        assert p2["line_offset"] == 3
        assert p2["compressed"].splitlines() == lines[3:5]

    def test_out_file(self, tmp_path):
        target = tmp_path / "fn.semz.txt"
        r = _api_compress_text(
            CORPUS_A, level="ultra", arch="x64", out_file=str(target)
        )
        assert "compressed" not in r
        assert r["file"] == str(target)
        inline = _api_compress_text(CORPUS_A, level="ultra", arch="x64")
        assert target.read_text(encoding="utf-8") == inline["compressed"]
        assert r["chars"] == len(inline["compressed"])


def test_jt_resolution_with_resolver():
    """#J：注入 resolver 后跳转表目标按标签输出；未注入则 unresolved。"""
    insns = [
        {"ea": 0x0, "text": "cmp x0, 2"},
        {"ea": 0x4, "text": "b.eq 0x20"},
        {"ea": 0x8, "text": "br x8"},
        {"ea": 0x20, "text": "ret"},
    ]
    r = compress_insns(
        insns, level="ultra", arch="arm64",
        jt_resolver=lambda ea: [0x20] if ea == 0x8 else None,
    )
    assert "#J L1: L2" in r["text"], r["text"]
    r2 = compress_insns(insns, level="ultra", arch="arm64")
    assert "#J L1: unresolved" in r2["text"], r2["text"]


def test_expand_macros_inline():
    """expand_macros=true：#P 定义/引用全部内联展开；默认保持宏形态。"""
    asm = ("mov rax,[rbx]\nadd rax,4\nmov [rbx],rax\n" * 3) + "retn"
    macro_form = _api_compress_text(asm, level="ultra", arch="x64")
    assert "#P " in macro_form["compressed"], macro_form["compressed"]

    flat = _api_compress_text(asm, level="ultra", arch="x64", expand_macros=True)
    assert "#P " not in flat["compressed"], flat["compressed"]
    refs = [
        ln for ln in flat["compressed"].splitlines()
        if ln.strip().startswith("P") and ln.strip()[1:].isdigit()
    ]
    assert not refs, refs
    # 展开后指令行数必须不少于宏形态
    macro_lines = len(macro_form["compressed"].splitlines())
    flat_lines = len(flat["compressed"].splitlines())
    assert flat_lines >= macro_lines


# ============================================================================
# loc_ 标签改写 / with_map / extract_block（0.2.1 新增）
# ============================================================================

from ida_mcp.compress import extract_blocks, format_blocks  # noqa: E402
from ida_mcp.compress.parse import parse_line  # noqa: E402

# 双 cascade 实战函数形态：分支目标被 IDA 命名为 loc_xxx（ARM64）
LOC_TARGET_INSNS = [
    {"ea": 0x1C79D4, "text": "cmp w26, 0x100"},
    {"ea": 0x1C79D8, "text": "b.ge loc_1C7A6C"},
    {"ea": 0x1C79DC, "text": "mov w0, 1"},
    {"ea": 0x1C79E0, "text": "ret"},
    {"ea": 0x1C7A6C, "text": "mov w0, 2"},
    {"ea": 0x1C7A70, "text": "ret"},
]


def test_parse_ida_code_label_operands():
    """IDA 自动代码标签操作数 → 0x 地址（裸符号 / short 前缀 / 颜色标签形态）。"""
    ins = parse_line("b.ge loc_1C7A6C", ea=0x1C79D8)
    assert ins.ops == ["0x1C7A6C"]
    ins = parse_line("jmp short loc_401040", ea=0x40101D)
    assert ins.ops == ["0x401040"]
    # IDA generate_disasm_line 原生形态：\x01( + 16 位隐藏 hex 载荷 + 符号名
    ins = parse_line(
        "b.ge \x01(00000000001C7A6Cloc_1C7A6C\x02(", ea=0x1C79D8
    )
    assert ins.ops == ["0x1C7A6C"], ins.ops
    # 命名函数/API 名不受影响
    ins = parse_line("bl sub_1C4000", ea=0x1C79DC)
    assert ins.ops == ["sub_1C4000"]


def test_loc_targets_become_labels_ultra():
    """ultra：loc_ 命名的分支目标必须渲染为 Ln 标签，全文无 loc_ 残留。"""
    r = compress_insns(LOC_TARGET_INSNS, level="ultra", arch="arm64")
    text = r["text"]
    assert "loc_" not in text.lower(), text
    m = re.search(r"gge (L\d+)", text)  # cmp+b.ge 融合行
    assert m, text
    assert re.search(rf"^{m.group(1)}:", text, re.M), text
    # 该地址不得进入常量池
    kline = next((ln for ln in text.splitlines() if ln.startswith("#K ")), "")
    assert "1C7A6C" not in kline, kline


def test_compress_map_exported():
    """map：L0=入口；压缩文本中每个 Ln 引用都有定义。"""
    r = compress_insns(LOC_TARGET_INSNS, level="ultra", arch="arm64")
    m = dict(r["map"])
    assert m["L0"] == 0x1C79D4
    assert m["L0"] == min(m.values())
    defined = set(m)
    refs = set(re.findall(r"\b(L\d+)\b", r["text"]))
    assert refs <= defined, (refs - defined, r["text"])


def test_with_map_api_param(tmp_path):
    """with_map=true：内联返回 map 字段；落盘时写 sidecar .map.json。"""
    r = _api_compress_text(CORPUS_A, level="ultra", arch="x64", with_map=True)
    assert r["map"]["L0"] == "0x401000", r.get("map")
    r0 = _api_compress_text(CORPUS_A, level="ultra", arch="x64")
    assert "map" not in r0

    target = tmp_path / "c.txt"
    rf = _api_compress_text(
        CORPUS_A, level="ultra", arch="x64", out_file=str(target), with_map=True
    )
    assert rf["map_file"] == str(target) + ".map.json"
    import json as _json

    side = _json.loads((tmp_path / "c.txt.map.json").read_text(encoding="utf-8"))
    assert side["L0"] == "0x401000"


def test_extract_blocks_helper():
    """extract_blocks：按标签切块；缺标签报错并列出可用标签；format 还原片段。"""
    text = compress_text(CORPUS_A, level="ultra", arch="x64")["text"]
    ex = extract_blocks(text, ["L0", "L2"])
    assert not ex.get("error")
    assert ex["blocks"]["L0"] and ex["blocks"]["L2"]
    assert any(ln.startswith("#SZ1") for ln in ex["header"])

    bad = extract_blocks(text, ["L999"])
    assert bad["error"]
    assert "L0" in bad["available"]

    frag = format_blocks(ex)
    assert "L0:" in frag and "L2:" in frag
    assert not any(ln.strip() == "L1:" for ln in frag.splitlines())


# ============================================================================
# SEMZ 可用性改进：annotate 宏模式 / hint 字段 / #summary 行 /
# ida://semz/manual 资源 / 工具 description 定位引导
# ============================================================================

def test_expand_macros_annotate():
    """expand_macros="annotate"：#P 定义/引用行保留，引用行尾带 `; =` 展开注释。"""
    asm = ("mov rax,[rbx]\nadd rax,4\nmov [rbx],rax\n" * 3) + "retn"
    r = _api_compress_text(asm, level="ultra", arch="x64", expand_macros="annotate")
    text = r["compressed"]
    assert "#P P0=" in text, text  # 定义行保留
    refs = [
        ln for ln in text.splitlines()
        if ln.strip().startswith("P0") and not ln.startswith("#")
    ]
    assert refs, text
    for ln in refs:
        assert "; = " in ln, ln           # 行尾展开注释
        assert "m a,[b]" in ln, ln        # 注释为展开后的纯指令序列
    # 默认 False 与 True 行为不变
    default = _api_compress_text(asm, level="ultra", arch="x64")
    assert "#P P0=" in default["compressed"]
    assert "; = " not in default["compressed"]
    flat = _api_compress_text(asm, level="ultra", arch="x64", expand_macros=True)
    assert "#P " not in flat["compressed"]


def test_hint_field_present_and_ordered(tmp_path):
    """hint 随响应返回、排在 compressed 之前；compressed 恒最后；落盘文件不含 hint。"""
    r = _api_compress_text(CORPUS_A, level="ultra", arch="x64")
    assert "hint" in r
    assert "decompile" in r["hint"] and "disasm" in r["hint"]
    keys = list(r)
    assert keys.index("hint") < keys.index("compressed")
    assert keys[-1] == "compressed"
    # 分页分支同样成立
    p = _api_compress_text(CORPUS_A, level="ultra", arch="x64", line_limit=3)
    assert "hint" in p and list(p)[-1] == "compressed"
    # 落盘：hint 在响应里，但不写进文件
    target = tmp_path / "hint.semz.txt"
    rf = _api_compress_text(CORPUS_A, level="ultra", arch="x64", out_file=str(target))
    assert "hint" in rf
    written = target.read_text(encoding="utf-8")
    assert "SEMZ is compressed disassembly" not in written


def test_ultra_summary_line():
    """ultra 头部第二行恒为 #summary，含 blocks=/macros=/consts=/jt= 字段。"""
    text = compress_text(CORPUS_A, level="ultra", arch="x64")["text"]
    lines = text.splitlines()
    assert lines[0].startswith("#SZ1 ")
    assert lines[1].startswith("#summary "), text
    for field in ("blocks=", "macros=", "consts=", "jt=0"):
        assert field in lines[1], lines[1]
    # 帧消隐语料带 frame 字段（语料 E #f=40）
    e_lines = compress_text(CORPUS_E, level="ultra")["text"].splitlines()
    assert e_lines[1].startswith("#summary ") and "frame=" in e_lines[1], e_lines[1]
    # 无帧语料省略 frame 字段（无标准序言的散指令）
    bare = compress_text("mov eax,1\nretn", level="ultra", arch="x86")["text"]
    assert "frame=" not in bare.splitlines()[1], bare


def test_ultra_summary_jt_indirect():
    """含间接跳转（br x8）的语料 #summary jt 字段非 0 且标 (indirect)。"""
    insns = [
        {"ea": 0x0, "text": "cmp x0, 2"},
        {"ea": 0x4, "text": "b.eq 0x20"},
        {"ea": 0x8, "text": "br x8"},
        {"ea": 0x20, "text": "ret"},
    ]
    r = compress_insns(
        insns, level="ultra", arch="arm64",
        jt_resolver=lambda ea: [0x20] if ea == 0x8 else None,
    )
    summary = r["text"].splitlines()[1]
    assert summary.startswith("#summary "), r["text"]
    assert "jt=1(indirect)" in summary, summary


def test_semz_manual_resource():
    """ida://semz/manual 资源返回速查文本，含定位与解码关键 token。"""
    from ida_mcp.api_resources import semz_manual_resource

    text = semz_manual_resource()
    for token in ("decompile", "disasm", "compress", "#SZ1", "#K", "#P", "#J", "#f", "g<cc>", "Ln"):
        assert token in text, token


def test_tool_descriptions_have_positioning():
    """MCP 工具 description（docstring 首行）含定位引导。"""
    import ida_mcp.api_analysis  # noqa: F401
    import ida_mcp.api_compress  # noqa: F401
    from ida_mcp.rpc import get_tool_specs

    specs = get_tool_specs()
    for name in ("compress_function", "compress_range", "compress_text", "extract_block"):
        assert "decompile" in specs[name].description, (name, specs[name].description)
    assert "semantics" in specs["decompile"].description
    assert "instruction" in specs["disasm"].description
    # disasm_text：混淆代码地面真相 + 警惕伪 C 误导的口径
    desc = specs["disasm_text"].description
    assert "obfuscated" in desc and "mislead" in desc, desc
    assert "decompile" in desc, desc


# ============================================================================
# disasm_text：原始汇编纯文本（纯 Python 辅助层可测；IDA 路径走 gateway 套件）
# ============================================================================

from ida_mcp.api_compress import _format_disasm_lines, _pack_plain  # noqa: E402

_DISASM_SAMPLE_INSNS = [
    {"ea": 0x401000, "text": "push rbp", "comment": None},
    {"ea": 0x401001, "text": "mov rbp, rsp", "comment": None},
    {"ea": 0x401004, "text": "call 0x402000", "comment": "sub_402000"},
    {"ea": 0x401009, "text": "retn", "comment": None},
]


def test_disasm_text_format_lines():
    """行格式 `0x<ea>: <text>`，有 comment 追加 ` ; <comment>`；无任何 SEMZ 头部。"""
    text = _format_disasm_lines(_DISASM_SAMPLE_INSNS)
    lines = text.splitlines()
    assert lines[0] == "0x401000: push rbp"
    assert lines[2] == "0x401004: call 0x402000 ; sub_402000"
    assert len(lines) == 4 and text.endswith("\n")
    assert not any(ln.startswith("#") for ln in lines), text  # 无 #SZ1/#K/#P 等 SEMZ 头


def test_disasm_text_registered():
    """disasm_text 经 @tool 注册，签名为 query 或 start+end 二选一。"""
    import inspect

    import ida_mcp.api_compress as ac
    from ida_mcp.rpc import get_tool_specs

    assert "disasm_text" in get_tool_specs()
    params = inspect.signature(ac.disasm_text).parameters
    for name in ("query", "start", "end", "line_offset", "line_limit", "out_file"):
        assert name in params, name
    assert params["query"].default is None


def test_disasm_text_pack_paging():
    """分页：line_total 自洽、切片正确、disasm 恒最后；无 compress 专有字段。"""
    text = _format_disasm_lines(_DISASM_SAMPLE_INSNS)
    full = _pack_plain(text, "fn", "0x401000", 4)
    assert list(full)[-1] == "disasm"
    assert full["disasm"] == text and full["truncated"] is False
    assert "stats" not in full and "level" not in full and "compressed" not in full

    p1 = _pack_plain(text, "fn", "0x401000", 4, line_limit=2)
    assert p1["line_total"] == 4 and p1["line_offset"] == 0
    assert p1["disasm"].splitlines() == text.splitlines()[:2]
    p2 = _pack_plain(text, "fn", "0x401000", 4, line_offset=2, line_limit=2)
    assert p2["line_offset"] == 2
    assert p2["disasm"].splitlines() == text.splitlines()[2:4]


def test_disasm_text_pack_out_file(tmp_path):
    """落盘与内联一致；落盘不回传 disasm。"""
    text = _format_disasm_lines(_DISASM_SAMPLE_INSNS)
    target = tmp_path / "fn.disasm.txt"
    r = _pack_plain(text, "fn", "0x401000", 4, out_file=str(target))
    assert "disasm" not in r
    assert r["file"] == str(target) and r["chars"] == len(text)
    assert target.read_text(encoding="utf-8") == text
