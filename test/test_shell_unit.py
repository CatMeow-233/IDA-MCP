"""Pure unit tests for the shell-analysis layer (no IDA, no gateway).

Covers: blobscan (magics/entropy/permutations), sigdb constant scan,
api_shell pure header parsers (ELF/PE/Mach-O + suspicious-constant filter).
Live-IDA smoke tests live in test_shell.py (marker=shell);
Unicorn runner tests live in test_emu_unit.py.
"""
from __future__ import annotations

import os
import random
import struct

import pytest

from ida_mcp import blobscan, sigdb
from ida_mcp import api_shell


# ============================================================================
# blobscan: magics
# ============================================================================

class TestMagics:
    def test_elf(self):
        data = b"\x00" * 16 + b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32
        hits = blobscan.find_magics(data, base=0x1000)
        assert any(h["type"] == "elf" and h["address"] == "0x1010" for h in hits)

    def test_pe_requires_chain(self):
        # bare MZ without PE chain must not hit
        bare = b"MZ" + b"\x00" * 256
        assert not any(h["type"] == "pe" for h in blobscan.find_magics(bare))
        # full chain hits
        pe = bytearray(0x400)
        pe[0:2] = b"MZ"
        struct.pack_into("<I", pe, 0x3C, 0x80)
        pe[0x80:0x84] = b"PE\x00\x00"
        assert any(h["type"] == "pe" for h in blobscan.find_magics(bytes(pe)))

    def test_dex_version_validation(self):
        good = b"dex\n035\x00" + b"\x00" * 64
        bad = b"dex\nzzz\x00" + b"\x00" * 64
        assert any(h["type"] == "dex" for h in blobscan.find_magics(good))
        assert not any(h["type"] == "dex" for h in blobscan.find_magics(bad))

    def test_lzma_alone_heuristic(self):
        real = bytes([0x5D]) + (0x800000).to_bytes(4, "little") + b"\xff" * 8 + b"\x00" * 64
        assert any(h["type"] == "lzma-alone" for h in blobscan.find_magics(real))
        # props == 0 is degenerate and must be rejected
        fake = bytes([0x00]) + (0x1000000).to_bytes(4, "little") + b"\xff" * 8 + b"\x00" * 64
        assert not any(h["type"] == "lzma-alone" for h in blobscan.find_magics(fake))
        # dict size not a power of two -> reject
        bad = bytes([0x5D]) + (12345).to_bytes(4, "little") + b"\xff" * 8 + b"\x00" * 64
        assert not any(h["type"] == "lzma-alone" for h in blobscan.find_magics(bad))

    def test_no_hits_on_zeros(self):
        assert blobscan.find_magics(b"\x00" * 4096) == []


# ============================================================================
# blobscan: entropy
# ============================================================================

class TestEntropy:
    def test_shannon_bounds(self):
        assert blobscan.shannon_entropy(b"\x00" * 512) == 0.0
        assert blobscan.shannon_entropy(bytes(range(256)) * 2) == pytest.approx(8.0)

    def test_high_entropy_region_detected(self):
        rng = random.Random(42)
        data = b"\x00" * 4096 + rng.randbytes(8192) + b"\x00" * 4096
        rep = blobscan.entropy_regions(data)
        high = [r for r in rep["regions"] if r["klass"] == "high"]
        assert high, "random blob must be flagged high-entropy"
        assert high[0]["size"] >= 8192 - 1024  # one window tolerance each side
        assert rep["stats"]["high_entropy_bytes"] >= 8192 - 1024

    def test_entropy_cliff_detected(self):
        rng = random.Random(7)
        data = rng.randbytes(8192) + b"\x00" * 8192
        rep = blobscan.entropy_regions(data)
        drops = [t for t in rep["transitions"] if t["kind"] == "drop"]
        assert drops and abs(drops[0]["offset"] - 8192) <= 512


# ============================================================================
# blobscan: permutation tables
# ============================================================================

class TestPermutations:
    def test_detects_custom_sbox(self):
        # a *custom* permutation (not any known S-box) must still be caught
        perm = bytes(sorted(range(256), key=lambda b: (b * 73 + 19) % 256))
        assert len(set(perm)) == 256
        data = b"\x11" * 512 + perm + b"\x11" * 512
        hits = blobscan.find_permutations(data)
        assert hits, "custom permutation table must be detected"
        assert hits[0]["offset"] <= 512 <= hits[0]["offset"] + hits[0]["length"]

    def test_rejects_non_permutation(self):
        data = b"\x00" * 512 + bytes([1, 2, 3] * 200)[:600]
        assert blobscan.find_permutations(data) == []


# ============================================================================
# sigdb
# ============================================================================

class TestSigDB:
    def test_aes_sbox(self):
        data = b"\x00" * 64 + bytes([
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
            0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]) + b"\x00" * 64
        hits = sigdb.scan_bytes(data, base=0x5000)
        assert any(h["family"] == "aes" and h["address"] == "0x5040" for h in hits)

    def test_chacha_sigma(self):
        data = b"junk junk " + b"expand 32-byte k" + b" junk"
        hits = sigdb.scan_bytes(data)
        assert any(h["name"] == "chacha/sigma" for h in hits)

    def test_sm4_and_family_filter(self):
        data = bytes([0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7,
                      0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05])
        assert any(h["family"] == "sm4" for h in sigdb.scan_bytes(data))
        assert sigdb.scan_bytes(data, families=["aes"]) == []

    def test_crc32_skips_zero_prefix(self):
        # table entries 1..5 (entry 0 is all zeros)
        data = struct.pack("<IIIII", 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x0)
        assert any(h["family"] == "crc32" for h in sigdb.scan_bytes(data))


# ============================================================================
# api_shell pure parsers
# ============================================================================

class TestHeaderParsers:
    def test_parse_real_sample_elf(self):
        sample = os.path.join(os.path.dirname(__file__), "..", "example", "MVP.sh")
        if not os.path.isfile(sample):
            pytest.skip("example/MVP.sh not present")
        with open(sample, "rb") as f:
            head = f.read(0x1000)
        assert api_shell.detect_format(head) == "elf"
        elf = api_shell.parse_elf_header(head)
        assert elf["ok"] and elf["class"] == 64
        assert elf["type"] == "DYN" and elf["machine"] == "aarch64"
        # the packer trait this whole layer exists to catch
        assert elf["no_section_headers"] is True

    def test_parse_pe_with_packer_section(self):
        pe = bytearray(0x400)
        pe[0:2] = b"MZ"
        struct.pack_into("<I", pe, 0x3C, 0x80)
        pe[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<H", pe, 0x84, 0x8664)   # x86-64
        struct.pack_into("<H", pe, 0x86, 1)        # 1 section
        struct.pack_into("<H", pe, 0x94, 0xF0)     # optional header size
        struct.pack_into("<H", pe, 0x98, 0x20B)    # PE32+
        sec = 0x98 + 0xF0
        pe[sec:sec + 8] = b".vmp0\x00\x00\x00\x00"
        struct.pack_into("<III", pe, sec + 8, 0x2000, 0x1000, 0x400)
        struct.pack_into("<I", pe, sec + 36, 0xE0000000)  # rwx
        info = api_shell.parse_pe_header(bytes(pe))
        assert info["ok"] and info["machine"] == "x86-64"
        assert "VMProtect" in info["packer_section_hints"]
        assert info["sections"][0]["exec"] and info["sections"][0]["write"]

    def test_macho_and_unknown(self):
        assert api_shell.parse_macho_header(b"\xcf\xfa\xed\xfe" + b"\x00" * 8)["ok"]
        assert not api_shell.parse_macho_header(b"NOPE")["ok"]
        assert api_shell.detect_format(b"\x00" * 64) == "unknown"


class TestSuspiciousConst:
    @pytest.mark.parametrize("v,expected", [
        (0x9E3779B9, True),    # TEA delta
        (0x1000, False),       # small
        (0xFFFFFFFF, False),   # all-ones mask
        (0x80000000, False),   # power of two
        (0xFFFFF000, False),   # page mask
        (0x61707865, True),    # chacha sigma dword
    ])
    def test_filter(self, v, expected):
        assert api_shell._is_suspicious_const(v) is expected
