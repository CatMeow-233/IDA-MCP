"""Live-IDA smoke tests for the shell-analysis tools (marker=shell).

Requires a running gateway + at least one registered IDA instance with the
updated plugin loaded (api_shell/api_emu registered). These tests are
sample-agnostic: they only assert contract shape, not sample-specific facts.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.shell


class TestShellLive:
    def test_triage_shell_contract(self, tool_caller):
        result = tool_caller("triage_shell", {"max_insns": 50000})
        assert isinstance(result, dict), result
        assert "error" not in result, result
        for key in ("format", "arch", "segments", "traits", "next"):
            assert key in result, f"missing {key} in triage_shell result"
        assert result["format"] in ("elf", "pe", "mach-o", "unknown")
        assert isinstance(result["traits"], list)

    def test_scan_regions_contract(self, tool_caller):
        result = tool_caller("scan_regions", {"min_region": 4096})
        assert isinstance(result, dict), result
        assert "error" not in result, result
        assert "high_entropy_regions" in result and "magics" in result
        assert result["bytes_scanned"] > 0

    def test_find_embedded_files_contract(self, tool_caller):
        result = tool_caller("find_embedded_files", {})
        assert isinstance(result, dict), result
        assert "error" not in result, result
        assert "count" in result and "files" in result

    def test_find_algo_signatures_contract(self, tool_caller):
        result = tool_caller("find_algo_signatures", {"with_xrefs": False})
        assert isinstance(result, dict), result
        assert "error" not in result, result
        assert "constants" in result and "permutation_tables" in result

    def test_scan_immediates_contract(self, tool_caller):
        result = tool_caller("scan_immediates", {"top": 5, "max_insns": 50000})
        assert isinstance(result, dict), result
        assert "error" not in result, result
        assert "functions" in result

    def test_dump_region_roundtrip(self, tool_caller):
        # dump the first 256 bytes of the lowest segment via list_segments
        segs = tool_caller("list_segments", {})
        items = segs.get("items") or []
        assert items, "no segments"
        base = min(items, key=lambda s: int(str(s["start_ea"]), 16))["start_ea"]
        result = tool_caller("dump_region", {"addr": base, "size": 256})
        assert isinstance(result, dict), result
        assert "error" not in result, result
        assert result["size"] == 256
        assert len(result["sha256"]) == 64

    def test_shell_playbook_resource_registered(self):
        # resource URIs are fetched through the MCP resource endpoint (covered
        # by manual live validation); here we assert registration statically
        # to avoid importing IDA-touching modules in the pytest process.
        import pathlib
        src = (pathlib.Path(__file__).parent.parent / "ida_mcp" / "api_resources.py").read_text(encoding="utf-8")
        assert 'ida://shell/playbook' in src
        assert "_SHELL_PLAYBOOK" in src
