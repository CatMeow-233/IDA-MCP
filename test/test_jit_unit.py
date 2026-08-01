"""ida_mcp.api_jit 纯单元测试（不依赖活 IDA / gateway）。

策略：
- _diff_bytes / _match_prologues 为纯函数，直接测；
- 工具经 .__wrapped__ 绕过 @idaread（无 IDA 时它会抛 RuntimeError），
  验证无 IDA 环境返回 {"error": ...}；
- diff_regions 的 文件 vs 文件 路径不依赖 IDA，用 tmp_path 实测。
"""
from __future__ import annotations

import pytest

from ida_mcp import api_jit
from ida_mcp.api_jit import _diff_bytes, _match_prologues


# ============================================================================
# _diff_bytes
# ============================================================================

def test_diff_identical():
    r = _diff_bytes(b"\x01\x02\x03", b"\x01\x02\x03")
    assert r["identical"] is True
    assert r["total_diff_bytes"] == 0
    assert r["diff_runs"] == []
    assert r["truncated"] is False


def test_diff_all_different_single_run():
    a = bytes(range(64))
    b = bytes((x ^ 0xFF) & 0xFF for x in range(64))
    r = _diff_bytes(a, b)
    assert r["identical"] is False
    assert r["total_diff_bytes"] == 64
    assert len(r["diff_runs"]) == 1
    run = r["diff_runs"][0]
    assert run["offset"] == 0
    assert run["length"] == 64
    # hex 预览截断到 32 字节
    assert run["a_hex"] == a[:32].hex()
    assert run["b_hex"] == b[:32].hex()
    assert len(run["a_hex"]) == 64  # 32 字节 * 2 hex 字符


def test_diff_middle_run():
    a = bytearray(b"\xAA" * 32)
    b = bytearray(a)
    b[10:14] = b"\x01\x02\x03\x04"
    r = _diff_bytes(bytes(a), bytes(b))
    assert r["total_diff_bytes"] == 4
    assert len(r["diff_runs"]) == 1
    run = r["diff_runs"][0]
    assert run["offset"] == 10
    assert run["length"] == 4
    assert run["b_hex"] == "01020304"


def test_diff_multiple_runs_and_max_runs():
    # 每 4 字节改 1 字节 → 多个单字节 run
    a = bytearray(b"\x00" * 64)
    b = bytearray(a)
    for i in range(0, 64, 4):
        b[i] = 0xFF
    r = _diff_bytes(bytes(a), bytes(b), max_runs=4)
    assert r["total_diff_bytes"] == 16  # 总差异数不受截断影响
    assert len(r["diff_runs"]) == 4
    assert r["truncated"] is True
    assert r["diff_runs"][0]["offset"] == 0
    assert r["diff_runs"][1]["offset"] == 4


def test_diff_tail_run_and_shorter_compare():
    # 长度不同：按较短者比，尾部 run 正常收尾
    a = b"\x01\x02\x03\x04\x05"
    b = b"\x01\x02\xFF\xFF"
    r = _diff_bytes(a, b)
    assert r["total_diff_bytes"] == 2
    assert r["diff_runs"] == [{
        "offset": 2, "length": 2, "a_hex": "0304", "b_hex": "ffff",
    }]


def test_diff_empty():
    r = _diff_bytes(b"", b"")
    assert r["identical"] is True
    assert r["diff_runs"] == []


# ============================================================================
# _match_prologues
# ============================================================================

def test_prologue_signatures():
    data = (
        b"\x90"                          # 0: nop
        + b"\x55\x48\x89\xE5"            # 1: push rbp; mov rbp,rsp
        + b"\x90" * 3                    # 5
        + b"\x55\x8B\xEC"                # 8: push ebp; mov ebp,esp
        + b"\x90"                        # 11
        + b"\x40\x53\x48\x83\xEC"        # 12: push rbx; sub rsp,imm8
        + b"\x48\x89\x5C\x24"            # 17: mov [rsp+XX], rbx
        + b"\x48\x83\xEC"                # 21: sub rsp, imm8
    )
    hits = _match_prologues(data)
    by_sig = {}
    for h in hits:
        by_sig.setdefault(h["signature"], []).append(h["offset"])
    assert by_sig["push_rbp_mov_rbp_rsp"] == [1]
    assert by_sig["push_ebp_mov_ebp_esp"] == [8]
    assert by_sig["push_rbx_sub_rsp"] == [12]
    assert by_sig["mov_rsp_rbx"] == [17]
    # 48 83 EC 同时是 push_rbx_sub_rsp(40 53 48 83 EC) 的后缀 → 重叠命中
    assert by_sig["sub_rsp_imm8"] == [14, 21]
    # 命中带字节回显
    hit = next(h for h in hits if h["signature"] == "push_rbp_mov_rbp_rsp")
    assert hit["bytes"] == "554889e5"


def test_prologue_alignment_heuristic():
    data = bytearray(b"\x90" * 64)
    data[15] = 0xC3          # ret，下一个 16 字节对齐地址 16 是疑似块入口
    data[19] = 0xE9          # jmp，下一个 4 字节对齐地址 20
    hits = _match_prologues(bytes(data))
    aligned = {(h["offset"], h["signature"]) for h in hits if h["signature"].startswith("aligned")}
    assert (16, "aligned_16_after_branch") in aligned
    assert (20, "aligned_4_after_branch") in aligned


def test_prologue_no_false_positive_on_empty():
    assert _match_prologues(b"\x00" * 32) == []


def test_prologue_sorted_by_offset():
    data = b"\x48\x83\xEC" + b"\x90" * 4 + b"\x55\x8B\xEC"
    hits = _match_prologues(data)
    offsets = [h["offset"] for h in hits]
    assert offsets == sorted(offsets)


# ============================================================================
# 无 IDA 时工具返回 error（.__wrapped__ 绕过 @idaread）
# ============================================================================

def test_scan_blocks_no_ida():
    r = api_jit.scan_blocks.__wrapped__("0x1000", "0x2000")
    assert "error" in r


def test_resolve_jump_slots_no_ida():
    r = api_jit.resolve_jump_slots.__wrapped__("0x1000", "0x2000")
    assert "error" in r


def test_find_refs_in_range_no_ida():
    r = api_jit.find_refs_in_range.__wrapped__("0x1000", "0x2000", "0x3000", "0x4000")
    assert "error" in r


def test_diff_regions_idb_source_no_ida():
    r = api_jit.diff_regions.__wrapped__("0x1000", "0x2000", size=0x100)
    assert "error" in r


def test_scan_blocks_bad_range_no_ida_still_error():
    # 无 IDA 时先做可用性检查，任何范围都返回 error
    r = api_jit.scan_blocks.__wrapped__("0x2000", "0x1000")
    assert "error" in r


# ============================================================================
# diff_regions 文件 vs 文件（不依赖 IDA，可完整实测）
# ============================================================================

def test_diff_regions_files(tmp_path):
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    data_a = bytes(range(64))
    data_b = bytearray(data_a)
    data_b[5] ^= 0xFF
    data_b[6] ^= 0xFF
    data_b[40] ^= 0xFF
    a.write_bytes(data_a)
    b.write_bytes(bytes(data_b))

    r = api_jit.diff_regions.__wrapped__(str(a), str(b))
    assert "error" not in r
    assert r["source_a"]["type"] == "file"
    assert r["source_b"]["type"] == "file"
    assert r["source_a"]["length"] == 64
    assert r["compared"] == 64
    assert r["identical"] is False
    assert r["total_diff_bytes"] == 3
    assert len(r["diff_runs"]) == 2
    assert r["diff_runs"][0]["offset"] == 5 and r["diff_runs"][0]["length"] == 2
    assert r["diff_runs"][1]["offset"] == 40 and r["diff_runs"][1]["length"] == 1


def test_diff_regions_files_identical(tmp_path):
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(b"\xDE\xAD" * 16)
    b.write_bytes(b"\xDE\xAD" * 16)
    r = api_jit.diff_regions.__wrapped__(str(a), str(b))
    assert r["identical"] is True
    assert "note" not in r


def test_diff_regions_files_different_lengths(tmp_path):
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(b"\x01" * 32)
    b.write_bytes(b"\x01" * 16)
    r = api_jit.diff_regions.__wrapped__(str(a), str(b))
    assert r["compared"] == 16
    assert r["identical"] is True
    assert "note" in r and "shorter" in r["note"]


def test_diff_regions_missing_file_and_bad_source(tmp_path):
    a = tmp_path / "a.bin"
    a.write_bytes(b"\x00" * 8)
    # 不存在的路径且不是合法地址 → error
    r = api_jit.diff_regions.__wrapped__(str(a), str(tmp_path / "nope.bin"))
    assert "error" in r
