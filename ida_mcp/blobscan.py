"""blobscan - generic blob / payload / table detection in binary buffers.

Pure Python, no IDA SDK dependency (mirrors ida_mcp/compress/ purity).

Three format-agnostic detectors:
    - find_magics        known file/container headers (data-driven table)
    - entropy_regions    Shannon entropy windows: high-entropy payloads and
                         high->low transitions (packed -> plaintext cliffs)
    - find_permutations  256-byte full permutations: S-box / RC4 candidates;
                         catches CUSTOM tables, not just known constants

Design note: a packer must write plaintext somewhere. These detectors do not
care which algorithm produced the data - that is what makes them generic.
"""
from __future__ import annotations

import math
from typing import Any, Callable, Dict, List, Optional


def _hex(addr: int) -> str:
    return f"0x{addr:X}"


# ============================================================================
# Shannon entropy
# ============================================================================

def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy (bits/byte, 0..8) of a byte string."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


# ============================================================================
# Magic signatures
# ============================================================================

def _check_pe(data: bytes, off: int) -> bool:
    """Validate MZ -> e_lfanew -> PE\\0\\0 chain."""
    if off + 0x40 > len(data):
        return False
    e_lfanew = int.from_bytes(data[off + 0x3C:off + 0x40], "little")
    pe_off = off + e_lfanew
    if e_lfanew < 0x40 or pe_off + 4 > len(data):
        return False
    return data[pe_off:pe_off + 4] == b"PE\x00\x00"


def _check_dex(data: bytes, off: int) -> bool:
    """dex\\n + 3 ASCII version digits + \\0."""
    if off + 8 > len(data):
        return False
    ver = data[off + 4:off + 7]
    return ver.isdigit() and data[off + 7] == 0


def _check_lzma_alone(data: bytes, off: int) -> bool:
    """LZMA-Alone stream: props byte < 9*5*5, plausible LE dict size.

    Heuristic only - medium confidence. Note this catches the *container*
    layout; a modified LZMA payload still starts with a props-like byte in
    most shell implementations.
    """
    if off + 13 > len(data):
        return False
    props = data[off]
    if props >= 9 * 5 * 5:
        return False
    # proper LZMA props decomposition: props = lc + lp*9 + pb*45,
    # with lc<=8, lp<=4, pb<=4, lc+lp<=9
    pb, rem = divmod(props, 45)
    lp, lc = divmod(rem, 9)
    if pb > 4 or lp > 4 or lc > 8 or lc + lp > 9:
        return False
    if props == 0:
        # lc=lp=pb=0 is legal but never emitted by real encoders
        return False
    dict_size = int.from_bytes(data[off + 1:off + 5], "little")
    # real dict sizes are round powers of two, >= 4KB in practice
    if dict_size < 0x1000 or dict_size > (1 << 30):
        return False
    if dict_size & (dict_size - 1) != 0:
        return False
    return True


_MAGICS: List[Dict[str, Any]] = [
    # name, signature, confidence, note, optional validator(data, off) -> bool
    {"name": "elf", "sig": b"\x7fELF", "confidence": "high",
     "note": "ELF executable/shared object", "check": None},
    {"name": "pe", "sig": b"MZ", "confidence": "high",
     "note": "PE executable (MZ+PE chain validated)", "check": _check_pe},
    {"name": "dex", "sig": b"dex\n", "confidence": "high",
     "note": "Dalvik executable", "check": _check_dex},
    {"name": "zip", "sig": b"PK\x03\x04", "confidence": "high",
     "note": "ZIP/APK archive member", "check": None},
    {"name": "xz", "sig": b"\xfd7zXZ\x00", "confidence": "high",
     "note": "XZ/LZMA2 container", "check": None},
    {"name": "lzma-alone", "sig": None, "confidence": "medium",
     "note": "LZMA-Alone stream (props/dict-size heuristic)", "check": _check_lzma_alone,
     "heuristic": True},
    {"name": "gzip", "sig": b"\x1f\x8b\x08", "confidence": "high",
     "note": "gzip stream", "check": None},
    {"name": "7z", "sig": b"7z\xbc\xaf\x27\x1c", "confidence": "high",
     "note": "7-Zip archive", "check": None},
    {"name": "zstd", "sig": b"\x28\xb5\x2f\xfd", "confidence": "high",
     "note": "Zstandard frame", "check": None},
    {"name": "lz4-frame", "sig": b"\x04\x22\x4d\x18", "confidence": "high",
     "note": "LZ4 frame", "check": None},
    {"name": "bz2", "sig": b"BZh", "confidence": "medium",
     "note": "bzip2 stream", "check": None},
    {"name": "rar", "sig": b"Rar!\x1a\x07", "confidence": "high",
     "note": "RAR archive", "check": None},
    {"name": "png", "sig": b"\x89PNG\r\n\x1a\n", "confidence": "high",
     "note": "PNG image", "check": None},
    {"name": "sqlite", "sig": b"SQLite format 3\x00", "confidence": "high",
     "note": "SQLite database", "check": None},
    {"name": "oat", "sig": b"oat\n", "confidence": "medium",
     "note": "Android OAT file", "check": None},
    {"name": "macho64-le", "sig": b"\xcf\xfa\xed\xfe", "confidence": "high",
     "note": "Mach-O 64-bit little-endian", "check": None},
    {"name": "macho32-le", "sig": b"\xce\xfa\xed\xfe", "confidence": "high",
     "note": "Mach-O 32-bit little-endian", "check": None},
    {"name": "macho64-be", "sig": b"\xfe\xed\xfa\xcf", "confidence": "high",
     "note": "Mach-O 64-bit big-endian", "check": None},
    {"name": "macho32-be", "sig": b"\xfe\xed\xfa\xce", "confidence": "high",
     "note": "Mach-O 32-bit big-endian", "check": None},
    {"name": "macho-fat|java-class", "sig": b"\xca\xfe\xba\xbe", "confidence": "medium",
     "note": "Mach-O universal binary or Java class (same magic)", "check": None},
]


def magics_table() -> List[Dict[str, Any]]:
    """Return the data-driven magic signature table (name/sig/confidence/note)."""
    return [dict(m) for m in _MAGICS]


def find_magics(
    data: bytes,
    base: int = 0,
    *,
    max_hits: int = 256,
) -> List[Dict[str, Any]]:
    """Scan data for known file/container magic signatures.

    Args:
        data: buffer to scan
        base: address corresponding to data[0] (for address reporting)
        max_hits: global cap on returned hits

    Returns:
        list of {type, offset, address, confidence, note} sorted by offset
    """
    hits: List[Dict[str, Any]] = []
    for entry in _MAGICS:
        sig: Optional[bytes] = entry["sig"]
        check: Optional[Callable[[bytes, int], bool]] = entry["check"]
        if sig is None:
            # heuristic-only entries (no fixed prefix): probe every offset
            for off in range(0, max(0, len(data) - 13)):
                if check is not None and check(data, off):
                    hits.append({
                        "type": entry["name"],
                        "offset": off,
                        "address": _hex(base + off),
                        "confidence": entry["confidence"],
                        "note": entry["note"],
                    })
                    if len(hits) >= max_hits:
                        return sorted(hits, key=lambda h: h["offset"])
            continue
        start = 0
        while True:
            off = data.find(sig, start)
            if off < 0:
                break
            start = off + 1
            if check is not None and not check(data, off):
                continue
            hits.append({
                "type": entry["name"],
                "offset": off,
                "address": _hex(base + off),
                "confidence": entry["confidence"],
                "note": entry["note"],
            })
            if len(hits) >= max_hits:
                return sorted(hits, key=lambda h: h["offset"])
    return sorted(hits, key=lambda h: h["offset"])


# ============================================================================
# Entropy regions
# ============================================================================

def entropy_regions(
    data: bytes,
    base: int = 0,
    *,
    window: int = 512,
    min_region: int = 1024,
    high: float = 7.0,
    low: float = 4.5,
    max_regions: int = 128,
) -> Dict[str, Any]:
    """Classify data into high/mid/low entropy regions and entropy cliffs.

    High entropy (~8) suggests compressed/encrypted payload; a high->low
    transition suggests a packed->plaintext boundary (e.g. where a shell
    stores data it has already decoded, or a header preceding a blob).

    Calibration note: empirical entropy of W iid uniform bytes is biased
    below 8.0 by ~255/(2*W*ln2) (W=512 -> ~7.64; W=256 -> ~7.28), so the
    default `high` threshold is 7.0 at window=512 to keep random-looking
    (packed/encrypted) data cleanly flagged without splitting it into noise.

    Returns:
        {"regions": [{offset, address, size, avg_entropy, klass}],
         "transitions": [{offset, address, from_entropy, to_entropy, kind}],
         "stats": {"window", "high_entropy_bytes", "total_bytes"}}
    """
    total = len(data)
    if total < window:
        return {"regions": [], "transitions": [],
                "stats": {"window": window, "high_entropy_bytes": 0, "total_bytes": total}}

    # per-window classification
    wins: List[tuple] = []  # (offset, entropy, klass)
    for off in range(0, total - window + 1, window):
        ent = shannon_entropy(data[off:off + window])
        klass = "high" if ent >= high else ("low" if ent <= low else "mid")
        wins.append((off, ent, klass))

    # merge consecutive windows of the same class
    regions: List[Dict[str, Any]] = []
    cur_off, cur_ent_sum, cur_n, cur_klass = wins[0][0], wins[0][1], 1, wins[0][2]
    for off, ent, klass in wins[1:]:
        if klass == cur_klass:
            cur_ent_sum += ent
            cur_n += 1
        else:
            regions.append({
                "offset": cur_off,
                "address": _hex(base + cur_off),
                "size": cur_n * window,
                "avg_entropy": round(cur_ent_sum / cur_n, 3),
                "klass": cur_klass,
            })
            cur_off, cur_ent_sum, cur_n, cur_klass = off, ent, 1, klass
    regions.append({
        "offset": cur_off,
        "address": _hex(base + cur_off),
        "size": cur_n * window,
        "avg_entropy": round(cur_ent_sum / cur_n, 3),
        "klass": cur_klass,
    })

    regions = [r for r in regions if r["size"] >= min_region]
    regions.sort(key=lambda r: (-(r["klass"] == "high"), -r["size"]))
    regions = regions[:max_regions]

    # high->low / low->high cliffs (payload boundaries)
    transitions: List[Dict[str, Any]] = []
    for i in range(1, len(wins)):
        prev_ent, cur_ent = wins[i - 1][1], wins[i][1]
        delta = cur_ent - prev_ent
        if abs(delta) >= 1.5:
            transitions.append({
                "offset": wins[i][0],
                "address": _hex(base + wins[i][0]),
                "from_entropy": round(prev_ent, 3),
                "to_entropy": round(cur_ent, 3),
                "kind": "drop" if delta < 0 else "rise",
            })
    transitions = transitions[:max_regions]

    high_bytes = sum(window for w in wins if w[1] >= high)
    return {
        "regions": regions,
        "transitions": transitions,
        "stats": {
            "window": window,
            "high_entropy_bytes": high_bytes,
            "total_bytes": total,
        },
    }


# ============================================================================
# Permutation tables (custom S-box / RC4 detection)
# ============================================================================

def find_permutations(
    data: bytes,
    base: int = 0,
    *,
    size: int = 256,
    stride: int = 64,
    max_hits: int = 64,
) -> List[Dict[str, Any]]:
    """Find runs that are full 256-value byte permutations (S-box candidates).

    Unlike constant-signature matching this is algorithm-agnostic: ANY custom
    byte-substitution table is a permutation of 0..255. Overlapping hits are
    merged into a single region.

    Large buffers (>32MB) fall back to stride=256 to bound runtime.
    """
    total = len(data)
    if total < size:
        return []
    if total > 32 * 1024 * 1024:
        stride = max(stride, 256)

    hits: List[Dict[str, Any]] = []
    for off in range(0, total - size + 1, stride):
        chunk = data[off:off + size]
        if len(set(chunk)) != size:
            continue
        # merge with previous hit when overlapping/adjacent
        if hits and off <= hits[-1]["offset"] + hits[-1]["length"]:
            prev = hits[-1]
            prev["length"] = off + size - prev["offset"]
        else:
            hits.append({
                "offset": off,
                "address": _hex(base + off),
                "length": size,
                "kind": f"perm{size}",
                "confidence": "medium",
                "note": "256-byte full permutation (S-box / RC4-state candidate)",
            })
            if len(hits) >= max_hits:
                break
    for h in hits:
        h["address"] = _hex(base + h["offset"])
    return hits


# ============================================================================
# Combined scan
# ============================================================================

def scan(
    data: bytes,
    base: int = 0,
    *,
    magics: bool = True,
    entropy: bool = True,
    perms: bool = True,
    min_region: int = 1024,
) -> Dict[str, Any]:
    """Run all enabled detectors over a buffer and return a combined report."""
    report: Dict[str, Any] = {
        "base": _hex(base),
        "size": len(data),
    }
    if magics:
        report["magics"] = find_magics(data, base)
    if entropy:
        ent = entropy_regions(data, base, min_region=min_region)
        report["entropy"] = ent
    if perms:
        report["permutations"] = find_permutations(data, base)
    report["summary"] = {
        "magic_hits": len(report.get("magics", [])),
        "perm_hits": len(report.get("permutations", [])),
        "high_entropy_bytes": report.get("entropy", {}).get("stats", {}).get("high_entropy_bytes", 0),
    }
    return report
