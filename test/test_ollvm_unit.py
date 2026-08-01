"""ida_mcp.api_ollvm 纯单元测试（不依赖活 IDA / gateway）。

策略：capstone 缺失时仅跳过 capstone 相关用例；_score_metrics / _find_opaque_predicates
均为纯函数，直接构造输入测试。
"""
from __future__ import annotations

import pytest

from ida_mcp.api_ollvm import (
    LightInsn,
    _find_opaque_predicates,
    _same_reg_operands,
    _score_metrics,
)

capstone = pytest.importorskip("capstone")
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BASE = 0x1000


def _disasm(hexbytes: str, base: int = BASE):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    return list(md.disasm(bytes.fromhex(hexbytes), base))


# ---------------------------------------------------------------------------
# _score_metrics
# ---------------------------------------------------------------------------

NORMAL_METRICS = {
    "instructions": 400,
    "cmov_count": 1,
    "cmov_density": 0.0025,   # <1%
    "opaque_pred_hits": 0,
    "blocks": 12,
    "calls": 8,
    "dispatcher_max_fanin": 2,
    "state_var_cmp_max": 2,
}

OLLVM_METRICS = {
    "instructions": 2000,
    "cmov_count": 160,
    "cmov_density": 0.08,     # 8%
    "opaque_pred_hits": 6,
    "blocks": 80,
    "calls": 2,
    "dispatcher_max_fanin": 9,
    "state_var_cmp_max": 12,
}


def test_score_normal():
    score, verdict = _score_metrics(NORMAL_METRICS)
    assert score == 0
    assert verdict == "normal"


def test_score_obvious_ollvm():
    score, verdict = _score_metrics(OLLVM_METRICS)
    # cmov 30 + opaque 40 + flat 15+10+5 = 100
    assert score == 100
    assert verdict == "likely_ollvm"


def test_score_verdict_boundaries():
    # 仅 cmov >=5% → 24 分 → normal 上沿之下
    m = dict(NORMAL_METRICS, cmov_density=0.05)
    score, verdict = _score_metrics(m)
    assert score == 24
    assert verdict == "normal"

    # 24 + opaque 1 hit (8) = 32 → suspicious
    m = dict(m, opaque_pred_hits=1)
    score, verdict = _score_metrics(m)
    assert score == 32
    assert verdict == "suspicious"

    # suspicious 上界：32 + dispatcher 15 + flat blocks 10 + state 5 = 62 → likely_ollvm
    m = dict(m, dispatcher_max_fanin=6, blocks=40, calls=2, state_var_cmp_max=9)
    score, verdict = _score_metrics(m)
    assert score == 62
    assert verdict == "likely_ollvm"


def test_score_partial_signals():
    # 仅平坦化信号：15 + 10 + 5 = 30 → suspicious
    m = dict(NORMAL_METRICS, blocks=60, calls=1,
             dispatcher_max_fanin=7, state_var_cmp_max=10)
    score, verdict = _score_metrics(m)
    assert score == 30
    assert verdict == "suspicious"

    # opaque 命中封顶 40（>=5 处满分）
    m = dict(NORMAL_METRICS, opaque_pred_hits=100)
    score, verdict = _score_metrics(m)
    assert score == 40
    assert verdict == "suspicious"


# ---------------------------------------------------------------------------
# _find_opaque_predicates（LightInsn 路径，不依赖 capstone 对象）
# ---------------------------------------------------------------------------

def _L(addr, size, hexbytes, mn, ops):
    return LightInsn(addr, size, bytes.fromhex(hexbytes), mn, ops)


def test_same_reg_operands():
    assert _same_reg_operands("eax, eax") == "eax"
    assert _same_reg_operands("eax, ebx") is None
    assert _same_reg_operands("eax, 1") is None
    assert _same_reg_operands("dword ptr [rax], 1") is None


def test_xor_self_jz_always_jump():
    # xor eax, eax ; jz +2
    insns = [_L(BASE, 2, "31C0", "xor", "eax, eax"),
             _L(BASE + 2, 2, "7402", "jz", "0x%x" % (BASE + 6))]
    found = _find_opaque_predicates(insns)
    assert len(found) == 1
    assert found[0]["kind"] == "always_jump"
    assert found[0]["ea"] == BASE + 2
    assert found[0]["bytes"] == bytes.fromhex("7402")


def test_sub_self_jnz_never_jump():
    insns = [_L(BASE, 2, "29DB", "sub", "ebx, ebx"),
             _L(BASE + 2, 2, "7505", "jnz", "0x%x" % (BASE + 9))]
    found = _find_opaque_predicates(insns)
    assert len(found) == 1
    assert found[0]["kind"] == "never_jump"


def test_cmp_self_je_always_jump():
    insns = [_L(BASE, 2, "39DB", "cmp", "ebx, ebx"),
             _L(BASE + 2, 2, "7401", "je", "0x%x" % (BASE + 5))]
    found = _find_opaque_predicates(insns)
    assert len(found) == 1
    assert found[0]["kind"] == "always_jump"


def test_zero_chain_test_jz():
    # xor eax, eax ; test eax, eax ; jz ...
    insns = [_L(BASE, 2, "31C0", "xor", "eax, eax"),
             _L(BASE + 2, 2, "85C0", "test", "eax, eax"),
             _L(BASE + 4, 2, "7403", "jz", "0x%x" % (BASE + 9))]
    found = _find_opaque_predicates(insns)
    kinds = {(f["ea"], f["kind"]) for f in found}
    # xor;jz 不紧邻（中间隔 test），只有 test;jz 链命中
    assert kinds == {(BASE + 4, "always_jump")}


def test_no_false_positive_on_normal_branch():
    # test eax, eax ; jz  —— eax 未知，不得判定
    insns = [_L(BASE, 2, "85C0", "test", "eax, eax"),
             _L(BASE + 2, 2, "7402", "jz", "0x%x" % (BASE + 6))]
    assert _find_opaque_predicates(insns) == []

    # xor eax, ebx ; jz —— 非同寄存器，不得判定
    insns = [_L(BASE, 2, "31D8", "xor", "eax, ebx"),
             _L(BASE + 2, 2, "7402", "jz", "0x%x" % (BASE + 6))]
    assert _find_opaque_predicates(insns) == []

    # xor eax, eax ; mov ecx, 1 ; jz —— 非紧邻，不得判定
    insns = [_L(BASE, 2, "31C0", "xor", "eax, eax"),
             _L(BASE + 2, 5, "B901000000", "mov", "ecx, 1"),
             _L(BASE + 7, 2, "7402", "jz", "0x%x" % (BASE + 11))]
    assert _find_opaque_predicates(insns) == []


# ---------------------------------------------------------------------------
# _find_opaque_predicates（capstone CsInsn 真实解码路径）
# ---------------------------------------------------------------------------

def test_capstone_decode_end_to_end():
    # xor eax,eax (31 C0) ; jz +2 (74 02) ; cmp ebx,ebx (39 DB) ;
    # jnz +1 (75 01) ; test ecx,ecx (85 C9) ; jz +0 (74 00) ; ret (C3)
    code = "31C0" "7402" "39DB" "7501" "85C9" "7400" "C3"
    insns = _disasm(code)
    found = _find_opaque_predicates(insns)
    by_ea = {f["ea"]: f["kind"] for f in found}
    # jz @+2 必跳；jnz 必不跳；test ecx,ecx 无清零链 → 不判定
    assert by_ea == {BASE + 2: "always_jump", BASE + 6: "never_jump"}
    # 每个命中带原始字节，供 patch 使用
    for f in found:
        assert len(f["bytes"]) == f["size"] == 2
