"""ida_mcp.api_dump 纯单元测试（不依赖活 IDA / gateway）。

只测无 IDA 依赖的纯逻辑：_parse_ranges 范围解析、_find_entry_candidates
入口启发式、_load_dump_impl 在无 IDA 时的 error 返回。
"""
from __future__ import annotations

import pytest

from ida_mcp import api_dump


# ============================================================================
# _parse_ranges
# ============================================================================

class TestParseRanges:
    def test_dash_form(self):
        r = api_dump._parse_ranges("0x7f0000-0x7f2000")
        assert r["ok"] is True
        assert r["ranges"] == [(0x7F0000, 0x7F2000)]

    def test_plus_form(self):
        r = api_dump._parse_ranges("0x800000+0x1000")
        assert r["ok"] is True
        assert r["ranges"] == [(0x800000, 0x801000)]

    def test_comma_separated(self):
        r = api_dump._parse_ranges("0x7f0000-0x7f2000, 0x800000+0x1000")
        assert r["ok"] is True
        assert r["ranges"] == [(0x7F0000, 0x7F2000), (0x800000, 0x801000)]

    def test_bare_address_is_one_page(self):
        r = api_dump._parse_ranges("0x9000")
        assert r["ok"] is True
        assert r["ranges"] == [(0x9000, 0xA000)]

    def test_list_input(self):
        r = api_dump._parse_ranges(["0x1000-0x2000", "0x3000+0x100", 0x5000])
        assert r["ok"] is True
        assert r["ranges"] == [(0x1000, 0x2000), (0x3000, 0x3100), (0x5000, 0x6000)]

    def test_decimal_and_trailing_h(self):
        r = api_dump._parse_ranges("4096-8192, 3000h+100h")
        assert r["ok"] is True
        assert r["ranges"] == [(4096, 8192), (0x3000, 0x3100)]

    def test_empty(self):
        assert api_dump._parse_ranges("")["ok"] is False
        assert api_dump._parse_ranges([])["ok"] is False

    def test_invalid_token(self):
        assert api_dump._parse_ranges("zzzz")["ok"] is False
        assert api_dump._parse_ranges("0x1000-zzz")["ok"] is False

    def test_end_le_start(self):
        r = api_dump._parse_ranges("0x2000-0x1000")
        assert r["ok"] is False
        assert "end <= start" in r["error"]

    def test_bad_type(self):
        assert api_dump._parse_ranges(12345)["ok"] is False


# ============================================================================
# _find_entry_candidates
# ============================================================================

class TestFindEntryCandidates:
    def test_pe_magic(self):
        data = b"MZ" + b"\x00" * 0x100
        cands = api_dump._find_entry_candidates(data, base=0x400000)
        assert len(cands) == 1
        assert cands[0]["kind"] == "pe"
        assert cands[0]["offset"] == 0
        assert cands[0]["address"] == "0x400000"

    def test_elf_magic(self):
        data = b"\x7fELF" + b"\x00" * 0x100
        cands = api_dump._find_entry_candidates(data, base=0x1000)
        assert cands[0]["kind"] == "elf"

    def test_prologue_x64(self):
        data = b"\x90" * 0x40 + bytes.fromhex("554889E5") + b"\x90" * 0x10
        cands = api_dump._find_entry_candidates(data, base=0x1000)
        assert cands[0]["offset"] == 0x40
        assert cands[0]["kind"] == "prologue_x64"
        assert cands[0]["address"] == "0x1040"

    def test_prologue_multiple_in_order(self):
        data = (
            b"\x90" * 0x10
            + bytes.fromhex("558BEC")          # x86 序言 @0x10
            + b"\x90" * 0x20
            + bytes.fromhex("40534883EC20")    # x64 push rbx; sub rsp,0x20 @0x33
        )
        cands = api_dump._find_entry_candidates(data, base=0)
        offsets = [c["offset"] for c in cands]
        assert offsets == sorted(offsets)
        assert 0x10 in offsets
        assert 0x33 in offsets

    def test_max_candidates(self):
        data = bytes.fromhex("554889E5") * 10  # 10 个序言
        cands = api_dump._find_entry_candidates(data, base=0, max_candidates=3)
        assert len(cands) == 3

    def test_no_match(self):
        assert api_dump._find_entry_candidates(b"\x00" * 0x100, base=0) == []

    def test_empty_data(self):
        assert api_dump._find_entry_candidates(b"", base=0) == []


# ============================================================================
# _load_dump_impl 无 IDA 环境
# ============================================================================

class TestLoadDumpImplNoIda:
    def test_no_ida_returns_error(self):
        assert api_dump.ida_segment is None, "本测试要求在无 IDA 环境运行"
        r = api_dump._load_dump_impl(b"\x90" * 16, 0x10000, "seg", "rwx", 64, "CODE")
        assert "error" in r

    def test_tool_raises_outside_ida(self, tmp_path):
        """@idawrite 包装在无 IDA 时应抛 RuntimeError（execute_sync 不可用）。"""
        f = tmp_path / "dump.bin"
        f.write_bytes(b"\x90" * 16)
        with pytest.raises(RuntimeError):
            api_dump.load_memory_dump(str(f), "0x10000")


# ============================================================================
# capstone 预览链路（可选依赖守护）
# ============================================================================

def test_capstone_disasm_preview():
    pytest.importorskip("capstone")
    from ida_mcp import codeforce

    # push rbp; mov rbp, rsp; ret
    r = codeforce.capstone_disasm_range(
        0x1000, bytes.fromhex("554889E5C3"), arch="x64", max_instructions=100
    )
    assert "error" not in r
    texts = [i["text"] for i in r["instructions"]]
    assert any("push" in t for t in texts)
    assert any("ret" in t for t in texts)
