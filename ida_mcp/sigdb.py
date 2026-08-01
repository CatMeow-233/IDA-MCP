"""sigdb - known crypto/compression constant signatures (fingerprint layer 1).

Pure Python, no IDA SDK dependency.

Scope honesty: this module only catches STOCK algorithms carrying their exact
constant tables. Modified or custom algorithms do not have these byte
patterns - those are caught by blobscan's statistical detectors (layer 2)
and api_shell.scan_immediates (layer 3). See instructor/SHELL_PLAYBOOK.md.

Table-driven: each entry is {family, name, sig, confidence, note}.
Constants are built with struct.pack so endianness is explicit.
"""
from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional


def _I(*vals: int) -> bytes:
    """Pack little-endian dwords."""
    return struct.pack("<" + "I" * len(vals), *vals)


def _Q(*vals: int) -> bytes:
    """Pack little-endian qwords."""
    return struct.pack("<" + "Q" * len(vals), *vals)


_SIGNATURES: List[Dict[str, Any]] = [
    # ---- symmetric ciphers -------------------------------------------------
    {"family": "aes", "name": "aes/sbox",
     "sig": bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                   0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]),
     "confidence": "high", "note": "AES S-box (encryption)"},
    {"family": "aes", "name": "aes/inv_sbox",
     "sig": bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
                   0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB]),
     "confidence": "high", "note": "AES inverse S-box (decryption)"},
    {"family": "aes", "name": "aes/te0",
     "sig": _I(0xA56363C6, 0x847C7CF8, 0x997777EE, 0x8D7B7BF6),
     "confidence": "high", "note": "AES Te0 T-table (optimized encryption)"},
    {"family": "aes", "name": "aes/td0",
     "sig": _I(0x51F4A750, 0x7E416553, 0x1A17A4C3, 0x3A275E96),
     "confidence": "high", "note": "AES Td0 T-table (optimized decryption)"},
    {"family": "sm4", "name": "sm4/sbox",
     "sig": bytes([0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7,
                   0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05]),
     "confidence": "high", "note": "SM4 S-box (common in CN commercial shells)"},
    {"family": "zuc", "name": "zuc/s0",
     "sig": bytes([0x3E, 0x72, 0x5B, 0x47, 0xCA, 0xE0, 0x00, 0x33,
                   0x04, 0xD1, 0x54, 0x98, 0x09, 0xB9, 0x6D, 0xCB]),
     "confidence": "high", "note": "ZUC stream cipher S0 box"},

    # ---- stream ciphers ----------------------------------------------------
    {"family": "chacha", "name": "chacha/sigma",
     "sig": b"expand 32-byte k",
     "confidence": "high", "note": "ChaCha20/XChaCha sigma constant"},
    {"family": "chacha", "name": "chacha/tau",
     "sig": b"expand 16-byte k",
     "confidence": "high", "note": "ChaCha20 tau constant (128-bit key)"},

    # ---- hash digests ------------------------------------------------------
    {"family": "sha256", "name": "sha256/K",
     "sig": _I(0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5),
     "confidence": "high", "note": "SHA-224/256 round constants"},
    {"family": "sha512", "name": "sha512/K",
     "sig": _Q(0x428A2F98D728FA22, 0x7137449123EF65CD),
     "confidence": "high", "note": "SHA-384/512 round constants"},
    {"family": "md5", "name": "md5/K",
     "sig": _I(0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE),
     "confidence": "high", "note": "MD5 sine table"},
    {"family": "crc32", "name": "crc32/ieee",
     # entries 1..5 (entry 0 is all-zero, a weak prefix)
     "sig": _I(0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419),
     "confidence": "high", "note": "CRC32-IEEE lookup table (+4 into table)"},

    # ---- hashing (non-crypto) ---------------------------------------------
    {"family": "xxhash", "name": "xxhash64/primes",
     "sig": _Q(0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F),
     "confidence": "high", "note": "XXH64 prime pair"},
    {"family": "xxhash", "name": "xxhash32/primes",
     "sig": _I(0x9E3779B1, 0x85EBCA77),
     "confidence": "medium", "note": "XXH32 prime pair"},

    # ---- encodings ---------------------------------------------------------
    {"family": "base64", "name": "base64/std",
     "sig": b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
     "confidence": "high", "note": "Base64 standard alphabet"},
    {"family": "base64", "name": "base64/url",
     "sig": b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
     "confidence": "high", "note": "Base64 URL-safe alphabet"},
]

# NOTE on LZMA: stock LZMA carries no large static constant table - its
# probability models are built at runtime. LZMA-family detection therefore
# lives in layer 2/3 (range-coder immediates: kTopValue 1<<24, kBitModelTotal
# 1<<11, init 1024, table stride 768/1846). Do not add weak byte sigs here.


def signatures() -> List[Dict[str, Any]]:
    """Return a copy of the signature table."""
    return [dict(s) for s in _SIGNATURES]


def scan_bytes(
    data: bytes,
    base: int = 0,
    *,
    families: Optional[List[str]] = None,
    max_per_sig: int = 16,
) -> List[Dict[str, Any]]:
    """Scan a buffer for known algorithm constant signatures.

    Args:
        data: buffer to scan
        base: address corresponding to data[0]
        families: optional family filter (e.g. ["aes", "chacha"])
        max_per_sig: cap of hits per signature

    Returns:
        list of {family, name, offset, address, length, confidence, note}
        sorted by offset.
    """
    hits: List[Dict[str, Any]] = []
    for entry in _SIGNATURES:
        if families and entry["family"] not in families:
            continue
        sig: bytes = entry["sig"]
        found = 0
        start = 0
        while found < max_per_sig:
            off = data.find(sig, start)
            if off < 0:
                break
            start = off + 1
            found += 1
            hits.append({
                "family": entry["family"],
                "name": entry["name"],
                "offset": off,
                "address": f"0x{base + off:X}",
                "length": len(sig),
                "confidence": entry["confidence"],
                "note": entry["note"],
            })
    return sorted(hits, key=lambda h: h["offset"])
