"""Shell/packer analysis API - triage, fingerprints, carving, layer extraction.

Provides tools:
    - triage_shell          one-shot packer trait report (PE/ELF/Mach-O)
    - scan_regions          entropy+magic payload-region scan of data segments
    - find_embedded_files   embedded file magic scan over all segments
    - find_algo_signatures  3-layer algorithm fingerprint scan
    - scan_immediates       per-function immediate-constant profiling
    - dump_region           dump IDB memory to a file
    - extract_layer         dump + hand off to open_in_ida for the next layer

Design principles (see instructor/SHELL_PLAYBOOK.md):
    - capability-generic: no per-sample hardcoding; format/arch branches only
    - chase data, not registers: entropy/magic/write-watch beats tracing
    - fingerprints have 3 layers; layer 1 (constants) never catches modified
      algorithms - layers 2 (statistical tables) and 3 (immediates) do
"""
from __future__ import annotations

import hashlib
import os
import struct
import tempfile
from typing import Annotated, Any, Dict, List, Optional, Tuple, Union

from .rpc import tool
from .sync import idaread
from .utils import parse_address, hex_addr, normalize_list_input
from . import blobscan, sigdb

# IDA module imports (guarded so pure helpers stay importable outside IDA)
try:
    import idaapi  # type: ignore
    import idc  # type: ignore
    import idautils  # type: ignore
    import ida_bytes  # type: ignore
    import ida_entry  # type: ignore
    import ida_funcs  # type: ignore
    import ida_ida  # type: ignore
    import ida_segment  # type: ignore
    import ida_ua  # type: ignore
except ImportError:
    idaapi = idc = idautils = ida_bytes = ida_entry = None  # type: ignore
    ida_funcs = ida_ida = ida_segment = ida_ua = None  # type: ignore

try:
    from .strings_cache import get_strings_cache
except ImportError:
    get_strings_cache = None  # type: ignore


# ============================================================================
# Pure header parsers (bytes -> facts; unit-testable without IDA)
# ============================================================================

_ELF_MACHINES = {
    0x03: "x86", 0x28: "arm", 0x3E: "x86-64", 0xB7: "aarch64", 0x08: "mips",
}
_ELF_TYPES = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}


def parse_elf_header(data: bytes) -> Dict[str, Any]:
    """Parse an ELF header (32/64-bit, LE/BE) into a facts dict."""
    if len(data) < 0x34 or data[:4] != b"\x7fELF":
        return {"ok": False, "error": "not an ELF"}
    klass = data[4]          # 1=32-bit, 2=64-bit
    endian = "little" if data[5] != 2 else "big"
    bo = "<" if endian == "little" else ">"
    e_type = struct.unpack_from(bo + "H", data, 16)[0]
    e_machine = struct.unpack_from(bo + "H", data, 18)[0]
    if klass == 2:
        entry = struct.unpack_from(bo + "Q", data, 0x18)[0]
        phoff = struct.unpack_from(bo + "Q", data, 0x20)[0]
        shoff = struct.unpack_from(bo + "Q", data, 0x28)[0]
        phnum = struct.unpack_from(bo + "H", data, 0x38)[0]
        shnum = struct.unpack_from(bo + "H", data, 0x3C)[0]
    else:
        entry = struct.unpack_from(bo + "I", data, 0x18)[0]
        phoff = struct.unpack_from(bo + "I", data, 0x1C)[0]
        shoff = struct.unpack_from(bo + "I", data, 0x20)[0]
        phnum = struct.unpack_from(bo + "H", data, 0x2C)[0]
        shnum = struct.unpack_from(bo + "H", data, 0x30)[0]
    return {
        "ok": True,
        "class": 64 if klass == 2 else 32,
        "endian": endian,
        "type": _ELF_TYPES.get(e_type, str(e_type)),
        "machine": _ELF_MACHINES.get(e_machine, hex(e_machine)),
        "entry": hex_addr(entry),
        "phnum": phnum,
        "shnum": shnum,
        "shoff": hex_addr(shoff),
        # the classic packer trait: section header table stripped
        "no_section_headers": shoff == 0 or shnum == 0,
    }


_PE_MACHINES = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "arm", 0xAA64: "arm64"}

# known packer/protector section-name -> family hints (data-driven, extend freely)
_PACKER_SECTION_HINTS = {
    ".vmp": "VMProtect", ".themida": "Themida/WinLicense", ".winlice": "WinLicense",
    ".enigma": "Enigma Protector", ".adata": "Themida", ".boom": "Boomerang",
    ".petite": "Petite", ".upx": "UPX", ".aspack": "ASPack", ".nsp": "NsPack",
    ".pec": "PECompact", ".seau": "SeauSFX", ".zhack": "ZProtect",
}


def parse_pe_header(data: bytes) -> Dict[str, Any]:
    """Parse a PE header into a facts dict (machine, sections, packer hints)."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return {"ok": False, "error": "not a PE (no MZ)"}
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 0x18 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return {"ok": False, "error": "no PE signature"}
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 0x14)[0]
    opt_off = e_lfanew + 0x18
    opt_magic = struct.unpack_from("<H", data, opt_off)[0] if opt_off + 2 <= len(data) else 0
    sec_off = opt_off + opt_size
    sections: List[Dict[str, Any]] = []
    hints: List[str] = []
    for i in range(min(nsec, 96)):
        off = sec_off + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].rstrip(b"\x00").decode("latin-1", "replace")
        vsize, _vaddr, rawsize = struct.unpack_from("<III", data, off + 8)
        chars = struct.unpack_from("<I", data, off + 36)[0]
        sections.append({
            "name": name,
            "vsize": vsize,
            "raw_size": rawsize,
            "exec": bool(chars & 0x20000000),
            "write": bool(chars & 0x80000000),
        })
        low = name.lower()
        for pat, fam in _PACKER_SECTION_HINTS.items():
            if low.startswith(pat) and fam not in hints:
                hints.append(fam)
    return {
        "ok": True,
        "class": 64 if opt_magic == 0x20B else 32,
        "machine": _PE_MACHINES.get(machine, hex(machine)),
        "num_sections": nsec,
        "sections": sections,
        "packer_section_hints": hints,
    }


def parse_macho_header(data: bytes) -> Dict[str, Any]:
    """Minimal Mach-O facts (magic/cpu only - triage does not need more)."""
    if len(data) < 8:
        return {"ok": False, "error": "too small"}
    magic = data[:4]
    table = {
        b"\xcf\xfa\xed\xfe": ("64", "little"), b"\xce\xfa\xed\xfe": ("32", "little"),
        b"\xfe\xed\xfa\xcf": ("64", "big"), b"\xfe\xed\xfa\xce": ("32", "big"),
    }
    if magic == b"\xca\xfe\xba\xbe":
        return {"ok": True, "class": "fat", "note": "universal binary"}
    if magic not in table:
        return {"ok": False, "error": "not a Mach-O"}
    klass, endian = table[magic]
    bo = "<" if endian == "little" else ">"
    cputype = struct.unpack_from(bo + "I", data, 4)[0]
    cpus = {0x01000007: "x86-64", 0x0100000C: "arm64", 0x0C: "arm", 0x07: "x86"}
    return {"ok": True, "class": klass, "endian": endian,
            "machine": cpus.get(cputype, hex(cputype))}


def detect_format(data: bytes) -> str:
    """Return 'elf' | 'pe' | 'mach-o' | 'unknown' from header bytes."""
    if data[:4] == b"\x7fELF":
        return "elf"
    if len(data) >= 0x40 and data[:2] == b"MZ" and blobscan.find_magics(data[:4096]):
        for m in blobscan.find_magics(data[:4096]):
            if m["type"] == "pe":
                return "pe"
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",
                    b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce", b"\xca\xfe\xba\xbe"):
        return "mach-o"
    return "unknown"


# ============================================================================
# Suspicious-string pattern table (data-driven, case-insensitive substring)
# ============================================================================

_STRING_PATTERNS: Dict[str, List[str]] = {
    "self_load": ["/proc/self/exe", "/proc/self/maps", "/proc/self/status",
                  "linker64", "/system/bin/linker", "dlopen", "dlsym"],
    "anti_debug": ["ptrace", "tracerpid", "frida", "xposed", "substrate",
                   "magisk", "isdebuggerpresent", "ntqueryinformationprocess",
                   "checkremotedebuggerpresent"],
    "mem_exec": ["mprotect", "prot_exec", "virtualprotect", "virtualalloc"],
    "sandbox_env": ["superuser", "emulator", "goldfish", "ranchu", "vbox",
                    "vmware", "qemu", "genymotion"],
}

_SYSCALL_MNEMS = {"svc", "swi", "syscall", "sysenter", "int"}

# per-arch immediate watchlist: family -> constants (layer-3 fingerprints)
_IMM_WATCH: Dict[str, frozenset] = {
    "lzma/range-coder": frozenset({0x736, 0x300, 0x400, 0x800, 0x1000000, 0x800000, 0xFFFF0000}),
    "tea/xtea": frozenset({0x9E3779B9, 0x61C88647, 0xC6EF3720}),
    "chacha": frozenset({0x61707865, 0x3320646E, 0x79622D32, 0x6B206574}),
    "sha256/init": frozenset({0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A}),
    "md5/init": frozenset({0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476}),
    "crc32/poly": frozenset({0xEDB88320, 0x04C11DB7, 0x82F63B78}),
    "sm4/fk": frozenset({0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC}),
}


def _is_suspicious_const(v: int) -> bool:
    """Heuristic: random-looking baked constant (custom crypto/compression).

    Accepts non-round 32/64-bit values with high popcount; rejects powers of
    two, all-ones masks, small values, and address-like aligned values.
    """
    if v < 0x10000 or v > 0xFFFFFFFFFFFFFFFF:
        return False
    if v & (v - 1) == 0:                # power of two
        return False
    if (v + 1) & v == 0:                # all-ones mask
        return False
    if v & 0xFFF == 0:                  # page/mask-aligned
        return False
    pop = bin(v).count("1")
    need = 16 if v > 0xFFFFFFFF else 8
    return pop >= need


# ============================================================================
# Internal IDA helpers
# ============================================================================

def _require_ida() -> Optional[dict]:
    if ida_bytes is None or ida_segment is None:
        return {"error": "IDA runtime unavailable"}
    return None


def _spill_path(name: str) -> str:
    out_dir = os.path.join(tempfile.gettempdir(), "ida_mcp_out")
    os.makedirs(out_dir, exist_ok=True)
    return os.path.join(out_dir, name)


def _iter_segments() -> List[Dict[str, Any]]:
    segs: List[Dict[str, Any]] = []
    for ea in idautils.Segments():
        s = ida_segment.getseg(ea)
        if not s:
            continue
        segs.append({
            "name": ida_segment.get_segm_name(s),
            "start": s.start_ea,
            "end": s.end_ea,
            "size": s.end_ea - s.start_ea,
            "exec": bool(s.perm & ida_segment.SEGPERM_EXEC),
            "write": bool(s.perm & ida_segment.SEGPERM_WRITE),
            "read": bool(s.perm & ida_segment.SEGPERM_READ),
        })
    return segs


def _read_segment_bytes(seg: Dict[str, Any], cap: int = 64 * 1024 * 1024) -> Optional[bytes]:
    size = min(seg["size"], cap)
    if size <= 0:
        return None
    return ida_bytes.get_bytes(seg["start"], size)


def _code_xref_funcs(ea: int, cap: int = 8) -> List[str]:
    """Function names that hold code references to ea (deduped, capped)."""
    funcs: List[str] = []
    seen = set()
    try:
        for x in idautils.XrefsTo(ea, 0):
            fn = ida_funcs.get_func(x.frm)
            if fn is None:
                continue
            name = ida_funcs.get_func_name(fn.start_ea)
            if name and name not in seen:
                seen.add(name)
                funcs.append(name)
                if len(funcs) >= cap:
                    break
    except Exception:
        pass
    return funcs


def _walk_code_immediates(
    max_insns: int,
) -> Tuple[Dict[int, Dict[str, Any]], List[Dict[str, Any]], bool, int]:
    """Walk code instructions once; collect per-function immediates and
    syscall-mnemonic counts. Returns (func_imms, syscall_funcs, partial, n)."""
    func_imms: Dict[int, Dict[str, Any]] = {}
    syscall_funcs: Dict[str, int] = {}
    partial = False
    n_insns = 0
    for fea in idautils.Functions():
        fname = ida_funcs.get_func_name(fea) or hex_addr(fea)
        for ea in idautils.FuncItems(fea):
            n_insns += 1
            if n_insns > max_insns:
                return func_imms, _svc_top(syscall_funcs), True, n_insns
            mnem = (idc.print_insn_mnem(ea) or "").lower()
            if mnem in _SYSCALL_MNEMS:
                syscall_funcs[fname] = syscall_funcs.get(fname, 0) + 1
            for op in range(3):
                try:
                    if idc.get_operand_type(ea, op) != ida_ua.o_imm:
                        continue
                    val = idc.get_operand_value(ea, op)
                except Exception:
                    continue
                if not isinstance(val, int) or val < 0:
                    continue
                rec = func_imms.get(fea)
                if rec is None:
                    rec = func_imms.setdefault(fea, {"name": fname, "watch": {}, "suspicious": set()})
                for fam, consts in _IMM_WATCH.items():
                    if val in consts:
                        rec["watch"].setdefault(fam, set()).add(val)
                if _is_suspicious_const(val):
                    rec["suspicious"].add(val)
    return func_imms, _svc_top(syscall_funcs), partial, n_insns


def _svc_top(syscall_funcs: Dict[str, int], cap: int = 16) -> List[Dict[str, Any]]:
    return [{"function": f, "syscall_count": c}
            for f, c in sorted(syscall_funcs.items(), key=lambda kv: -kv[1])[:cap]]


# ============================================================================
# Tools
# ============================================================================

@tool
@idaread
def triage_shell(
    max_insns: Annotated[int, "Instruction budget for syscall/immediate scan"] = 400000,
) -> dict:
    """One-shot packer triage: format facts, segments, strings, traits, next steps."""
    err = _require_ida()
    if err:
        return err

    report: Dict[str, Any] = {}

    # ---- format / header facts --------------------------------------------
    input_file = None
    try:
        input_file = idaapi.get_input_file_path()
    except Exception:
        pass
    head = b""
    if input_file and os.path.isfile(input_file):
        try:
            with open(input_file, "rb") as f:
                head = f.read(0x1000)
        except Exception:
            head = b""
    if not head:
        segs0 = _iter_segments()
        if segs0:
            base = min(s["start"] for s in segs0)
            head = ida_bytes.get_bytes(base, 0x1000) or b""

    fmt = detect_format(head)
    facts: Dict[str, Any] = {}
    if fmt == "elf":
        facts = parse_elf_header(head)
    elif fmt == "pe":
        facts = parse_pe_header(head)
    elif fmt == "mach-o":
        facts = parse_macho_header(head)
    report["format"] = fmt
    report["header"] = facts

    arch = None
    bits = 0
    try:
        arch = ida_ida.inf_get_procname()
        bits = int(ida_ida.inf_get_app_bitness())
    except Exception:
        pass
    report["arch"] = arch
    report["bits"] = bits

    # ---- segments ----------------------------------------------------------
    segs = _iter_segments()
    code_bytes = sum(s["size"] for s in segs if s["exec"])
    data_bytes = sum(s["size"] for s in segs if not s["exec"])
    rwx = [s for s in segs if s["read"] and s["write"] and s["exec"]]
    report["segments"] = {
        "count": len(segs),
        "code_bytes": code_bytes,
        "data_bytes": data_bytes,
        "rwx": [{"name": s["name"], "start": hex_addr(s["start"]), "size": s["size"]} for s in rwx],
        "largest": [{"name": s["name"], "size": s["size"], "exec": s["exec"]}
                    for s in sorted(segs, key=lambda x: -x["size"])[:5]],
    }

    # ---- imports / exports / entries ---------------------------------------
    try:
        report["imports"] = int(idaapi.get_import_module_qty())
    except Exception:
        report["imports"] = None
    try:
        report["exports"] = int(ida_entry.get_entry_qty())
    except Exception:
        report["exports"] = None

    # ---- suspicious strings -------------------------------------------------
    string_hits: Dict[str, Any] = {}
    if get_strings_cache is not None:
        try:
            cache = get_strings_cache()
            for cat, pats in _STRING_PATTERNS.items():
                examples: List[dict] = []
                count = 0
                for ea, _ln, _st, text in cache:
                    low = str(text).lower()
                    if any(p in low for p in pats):
                        count += 1
                        if len(examples) < 5:
                            examples.append({"ea": hex_addr(ea), "text": str(text)[:80]})
                if count:
                    string_hits[cat] = {"count": count, "examples": examples}
        except Exception:
            pass
    report["string_hits"] = string_hits

    # ---- syscall/immediate one-pass scan ------------------------------------
    func_imms, svc_funcs, partial, n_insns = _walk_code_immediates(max_insns)
    report["syscall_scan"] = {
        "insns_scanned": n_insns,
        "partial": partial,
        "top_functions": svc_funcs,
    }

    # ---- traits --------------------------------------------------------------
    traits: List[Dict[str, str]] = []

    def _trait(tid: str, desc: str, hint: str) -> None:
        traits.append({"id": tid, "desc": desc, "hint": hint})

    if facts.get("no_section_headers"):
        _trait("no_section_headers", "ELF section header table stripped",
               "typical of packed Android executables; go to scan_regions")
    if rwx:
        _trait("rwx_segment", f"{len(rwx)} RWX segment(s): an unpacker writes code there",
               "emu_run/emu_call the entry chain; write-watch will catch the payload")
    if code_bytes and data_bytes > 4 * code_bytes:
        _trait("tiny_code_huge_data",
               f"code={code_bytes} data={data_bytes}: payload hides in data",
               "scan_regions to locate high-entropy payload blobs")
    if report.get("exports") == 0 and facts.get("type") in (None, "DYN", "EXEC"):
        _trait("no_exports", "no exported symbols: hardened/stripped binary",
               "entry points + init_array are your only leads")
    if "self_load" in string_hits:
        _trait("self_load_strings", "self-loading strings (/proc/self, linker, dlopen)",
               "the stub maps itself; chase mmap/mprotect writes")
    if "anti_debug" in string_hits:
        _trait("anti_debug_strings", "anti-debug/anti-hook strings present",
               "prefer Unicorn emulation over live debugging")
    if facts.get("packer_section_hints"):
        _trait("packer_sections",
               "packer section names: " + ", ".join(facts["packer_section_hints"]),
               "known protector - check playbook for family notes")
    tramp = [f for f in svc_funcs if f["syscall_count"] >= 3]
    if len(tramp) >= 2:
        _trait("syscall_trampolines",
               f"{len(tramp)} functions with >=3 syscalls: trampoline injection likely",
               "expect syscall-based monitoring/anti-debug; emulate, don't debug")
    report["traits"] = traits

    report["next"] = [
        "scan_regions() - locate payload blobs (entropy+magic) in data segments",
        "find_algo_signatures() - 3-layer fingerprint: constants/tables/immediates",
        "emu_call(decompressor, ...) - emulate, never hand-translate (2h cap rule)",
        "MCP resource ida://shell/playbook - full methodology",
    ]
    return report


@tool
@idaread
def scan_regions(
    min_region: Annotated[int, "Minimum region size in bytes"] = 1024,
    include_exec: Annotated[bool, "Also scan executable segments"] = False,
) -> dict:
    """Entropy+magic scan of data segments: locate payload blobs without any format knowledge."""
    err = _require_ida()
    if err:
        return err
    out_regions: List[dict] = []
    out_magics: List[dict] = []
    scanned = 0
    for seg in _iter_segments():
        if seg["exec"] and not include_exec:
            continue
        data = _read_segment_bytes(seg)
        if not data:
            continue
        scanned += len(data)
        ent = blobscan.entropy_regions(data, seg["start"], min_region=min_region)
        for r in ent["regions"]:
            if r["klass"] == "high":
                r = dict(r)
                r["segment"] = seg["name"]
                out_regions.append(r)
        for m in blobscan.find_magics(data, seg["start"]):
            m = dict(m)
            m["segment"] = seg["name"]
            out_magics.append(m)
    out_regions.sort(key=lambda r: -r["size"])
    return {
        "bytes_scanned": scanned,
        "high_entropy_regions": out_regions[:64],
        "magics": out_magics[:128],
        "hint": "high-entropy region = packed/encrypted payload candidate; "
                "feed its address to dump_region or watch it appear via emu write-watch",
    }


@tool
@idaread
def find_embedded_files() -> dict:
    """Scan all segments for embedded file magics (ELF/DEX/ZIP/XZ/GZIP/LZMA...)."""
    err = _require_ida()
    if err:
        return err
    hits: List[dict] = []
    for seg in _iter_segments():
        data = _read_segment_bytes(seg)
        if not data:
            continue
        for m in blobscan.find_magics(data, seg["start"]):
            m = dict(m)
            m["segment"] = seg["name"]
            hits.append(m)
    hits.sort(key=lambda h: int(h["address"], 16))
    return {"count": len(hits), "files": hits[:256],
            "hint": "dump_region(address, size) to carve; extract_layer to open in a new IDA instance"}


@tool
@idaread
def find_algo_signatures(
    with_xrefs: Annotated[bool, "Enrich each hit with referencing functions"] = True,
    perms: Annotated[bool, "Include statistical permutation-table detection (layer 2)"] = True,
) -> dict:
    """3-layer algorithm fingerprint scan over all segments (constants + statistical tables)."""
    err = _require_ida()
    if err:
        return err
    const_hits: List[dict] = []
    perm_hits: List[dict] = []
    for seg in _iter_segments():
        data = _read_segment_bytes(seg)
        if not data:
            continue
        for h in sigdb.scan_bytes(data, seg["start"]):
            h = dict(h)
            h["segment"] = seg["name"]
            if with_xrefs:
                h["referenced_by"] = _code_xref_funcs(seg["start"] + h["offset"])
            const_hits.append(h)
        if perms:
            for p in blobscan.find_permutations(data, seg["start"]):
                p = dict(p)
                p["segment"] = seg["name"]
                if with_xrefs:
                    p["referenced_by"] = _code_xref_funcs(seg["start"] + p["offset"])
                perm_hits.append(p)
    return {
        "constants": const_hits[:128],
        "permutation_tables": perm_hits[:64],
        "layers_note": "layer1=known constants (stock algos only), layer2=permutation "
                       "tables (custom S-boxes), layer3=scan_immediates() for code-level "
                       "constants (range-coder/crypto idioms, catches modified algos)",
        "hint": "referenced_by gives candidate decrypt/decompress functions - "
                "emulate them with emu_call, do not hand-translate",
    }


@tool
@idaread
def scan_immediates(
    top: Annotated[int, "Number of functions to return"] = 25,
    max_insns: Annotated[int, "Instruction budget"] = 400000,
) -> dict:
    """Layer-3 fingerprint: rank functions by baked constants (crypto/compression idioms)."""
    err = _require_ida()
    if err:
        return err
    func_imms, _svc, partial, n_insns = _walk_code_immediates(max_insns)
    ranked: List[dict] = []
    for fea, rec in func_imms.items():
        watch = {fam: sorted(hex_addr(v) for v in vals)
                 for fam, vals in rec["watch"].items()}
        susp = sorted(rec["suspicious"])[:8]
        score = 2 * sum(len(v) for v in rec["watch"].values()) + min(len(rec["suspicious"]), 5)
        if score <= 0:
            continue
        ranked.append({
            "function": rec["name"],
            "ea": hex_addr(fea),
            "score": score,
            "watch_hits": watch,
            "suspicious_constants": [hex_addr(v) for v in susp],
        })
    ranked.sort(key=lambda r: -r["score"])
    return {
        "insns_scanned": n_insns,
        "partial": partial,
        "functions": ranked[:top],
        "hint": "high-score functions are transform-loop candidates; verify with "
                "compress_function/disasm_text, then emu_call - never hand-translate",
    }


@tool
@idaread
def dump_region(
    addr: Annotated[Union[int, str], "Start address of the region"],
    size: Annotated[int, "Number of bytes to dump (max 64MB)"] = 4096,
    name: Annotated[Optional[str], "Output file name (default: dump_<addr>_<size>.bin)"] = None,
) -> dict:
    """Dump IDB memory to a file under %TEMP%/ida_mcp_out/ and return hash+preview."""
    err = _require_ida()
    if err:
        return err
    parsed = parse_address(addr)
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid address", "addr": addr}
    if size <= 0 or size > 64 * 1024 * 1024:
        return {"error": "size must be in 1..64MB"}
    start = parsed["value"]
    chunks: List[bytes] = []
    remaining = size
    cursor = start
    while remaining > 0:
        want = min(remaining, 1024 * 1024)
        data = ida_bytes.get_bytes(cursor, want)
        if data is None:
            break
        chunks.append(data)
        cursor += len(data)
        remaining -= len(data)
        if len(data) < want:
            break
    blob = b"".join(chunks)
    if not blob:
        return {"error": "no bytes read", "addr": hex_addr(start)}
    fname = name or f"dump_{start:X}_{len(blob):X}.bin"
    path = _spill_path(os.path.basename(fname))
    with open(path, "wb") as f:
        f.write(blob)
    return {
        "file": path,
        "address": hex_addr(start),
        "size": len(blob),
        "requested": size,
        "sha256": hashlib.sha256(blob).hexdigest(),
        "head_hex": blob[:32].hex(" "),
        "magics": blobscan.find_magics(blob, start)[:16],
        "note": "spilled files are temporary - delete after the task is done",
    }


@tool
@idaread
def extract_layer(
    addr: Annotated[Union[int, str], "Start address of the unpacked payload"],
    size: Annotated[int, "Payload size in bytes"],
    name: Annotated[Optional[str], "Output file name (e.g. layer2.so / classes.dex)"] = None,
) -> dict:
    """Dump a payload layer to disk and hand off to open_in_ida for parallel next-layer analysis."""
    dumped = dump_region(addr, size, name)
    if "error" in dumped:
        return dumped
    dumped["next_step"] = {
        "tool": "open_in_ida",
        "args": {"file_path": dumped["file"]},
        "why": "analyze this layer in a fresh IDA instance immediately - layers "
               "progress in parallel, never wait for full unpack of the current one",
    }
    return dumped
