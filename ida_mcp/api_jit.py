"""JIT API - translation cache / JIT shell analysis operations.

Provides tools:
    - scan_blocks        block entry scan (byte pattern or x86/x64 prologue signatures)
    - resolve_jump_slots lazy-resolution jump slot classification (heuristic)
    - find_refs_in_range full-cache reference scan (decision-point discovery)
    - diff_regions       compare two memory ranges or dump files
"""
from __future__ import annotations

import os
from typing import Annotated, Optional, Union, List, Dict, Any, Tuple

from .rpc import tool
from .sync import idaread
from .utils import parse_address, hex_addr

# IDA module imports
try:
    import ida_bytes  # type: ignore
    import ida_search  # type: ignore
    import ida_segment  # type: ignore
    import ida_ida  # type: ignore
    import idaapi  # type: ignore
except ImportError:
    ida_bytes = None
    ida_search = None
    ida_segment = None
    ida_ida = None
    idaapi = None

# ============================================================================
# 常量
# ============================================================================

MAX_SCAN_RANGE = 16 * 1024 * 1024   # scan_blocks 范围上限
MAX_REF_RANGE = 64 * 1024 * 1024    # find_refs_in_range 范围上限
RUN_HEX_PREVIEW = 32                # diff run 每侧最多展示的字节数

# x86/x64 函数序言签名（pattern 缺省时使用）
_PROLOGUE_SIGNATURES: List[Tuple[str, bytes]] = [
    ("push_rbp_mov_rbp_rsp", bytes.fromhex("554889E5")),  # push rbp; mov rbp, rsp
    ("push_ebp_mov_ebp_esp", bytes.fromhex("558BEC")),    # push ebp; mov ebp, esp
    ("push_rbx_sub_rsp", bytes.fromhex("40534883EC")),    # push rbx; sub rsp, imm8
    ("mov_rsp_rbx", bytes.fromhex("48895C24")),           # mov [rsp+XX], rbx
    ("sub_rsp_imm8", bytes.fromhex("4883EC")),            # sub rsp, imm8（无前缀变体）
]

# 对齐启发：前一字节为 ret/retn/jmp 时，对齐地址疑似块入口
_BRANCH_END_BYTES = (0xC3, 0xC2, 0xEB, 0xE9)


# ============================================================================
# 纯函数（可无 IDA 单测）
# ============================================================================

def _match_prologues(data: bytes) -> List[dict]:
    """在字节串中扫描 x86/x64 函数序言签名 + 对齐启发。

    Args:
        data: 待扫描的字节串

    Returns:
        [{"offset": int, "signature": str, "bytes": hex}]，按 offset 升序
    """
    results: List[dict] = []

    # 签名匹配：逐签名用 bytes.find 推进（C 速度）
    for name, sig in _PROLOGUE_SIGNATURES:
        pos = data.find(sig)
        while pos != -1:
            results.append({
                "offset": pos,
                "signature": name,
                "bytes": sig.hex(),
            })
            pos = data.find(sig, pos + 1)

    # 对齐启发：4/16 字节对齐且前一字节是 ret/jmp 分支结束
    for off in range(4, len(data), 4):
        if data[off - 1] in _BRANCH_END_BYTES:
            results.append({
                "offset": off,
                "signature": "aligned_16_after_branch" if off % 16 == 0 else "aligned_4_after_branch",
                "bytes": None,
            })

    results.sort(key=lambda r: r["offset"])
    return results


def _diff_bytes(a: bytes, b: bytes, max_runs: int = 128) -> dict:
    """对比两个字节串（按较短者），连续不同字节合并为 run。

    Args:
        a: 字节串 A
        b: 字节串 B
        max_runs: 最多返回的 run 数，超出截断并标 truncated

    Returns:
        {identical, total_diff_bytes, diff_runs: [{offset, length, a_hex, b_hex}], truncated}
    """
    n = min(len(a), len(b))
    runs: List[dict] = []
    total_diff = 0
    truncated = False

    run_start: Optional[int] = None
    for i in range(n):
        if a[i] != b[i]:
            total_diff += 1
            if run_start is None:
                run_start = i
        else:
            if run_start is not None:
                if len(runs) < max_runs:
                    length = i - run_start
                    runs.append({
                        "offset": run_start,
                        "length": length,
                        "a_hex": a[run_start:run_start + min(length, RUN_HEX_PREVIEW)].hex(),
                        "b_hex": b[run_start:run_start + min(length, RUN_HEX_PREVIEW)].hex(),
                    })
                else:
                    truncated = True
                run_start = None
    if run_start is not None:
        if len(runs) < max_runs:
            length = n - run_start
            runs.append({
                "offset": run_start,
                "length": length,
                "a_hex": a[run_start:run_start + min(length, RUN_HEX_PREVIEW)].hex(),
                "b_hex": b[run_start:run_start + min(length, RUN_HEX_PREVIEW)].hex(),
            })
        else:
            truncated = True

    return {
        "identical": total_diff == 0,
        "total_diff_bytes": total_diff,
        "diff_runs": runs,
        "truncated": truncated,
    }


# ============================================================================
# 内部辅助
# ============================================================================

def _ida_unavailable() -> dict:
    return {"error": "IDA modules unavailable (not running inside IDA?)"}


def _parse_range(base: Union[int, str], end: Union[int, str], max_size: int) -> Tuple[Optional[int], Optional[int], Optional[dict]]:
    """解析并校验 [base, end) 范围。"""
    pb = parse_address(base)
    if not pb["ok"] or pb["value"] is None:
        return None, None, {"error": "invalid base address", "base": base}
    pe = parse_address(end)
    if not pe["ok"] or pe["value"] is None:
        return None, None, {"error": "invalid end address", "end": end}
    b, e = pb["value"], pe["value"]
    if e <= b:
        return None, None, {"error": "end must be greater than base"}
    if e - b > max_size:
        return None, None, {
            "error": f"range too large (max {max_size} bytes)",
            "size": e - b,
        }
    return b, e, None


def _read_range(base: int, size: int) -> Optional[bytes]:
    """读取 IDB 内存范围，失败返回 None。"""
    try:
        data = ida_bytes.get_bytes(base, size)  # type: ignore[union-attr]
        return bytes(data) if data is not None else None
    except Exception:
        return None


def _is_big_endian() -> bool:
    try:
        return bool(ida_ida is not None and ida_ida.inf_is_be())
    except Exception:
        return False


def _slot_values(data: bytes, base: int, ptr_size: int, big_endian: bool):
    """按 ptr_size 对齐遍历槽位，yield (slot_addr, value)。"""
    order = "big" if big_endian else "little"
    count = len(data) // ptr_size
    for i in range(count):
        off = i * ptr_size
        yield base + off, int.from_bytes(data[off:off + ptr_size], order)


# ============================================================================
# 块入口扫描
# ============================================================================

@tool
@idaread
def scan_blocks(
    base: Annotated[Union[int, str], "Range start address"],
    end: Annotated[Union[int, str], "Range end address (exclusive)"],
    pattern: Annotated[Optional[str], "Byte pattern with wildcards (e.g. '48 8B ?? 48 89'); omit for x86/x64 prologue signature scan"] = None,
    max_results: Annotated[int, "Max results (1..4096)"] = 256,
) -> dict:
    """Block entry scan of a translation cache / JIT region: byte-pattern search or x86/x64 prologue signature + alignment heuristics.

    场景：带翻译缓存的壳（模拟器保护、动态翻译壳）里定位缓存块入口。
    - pattern 给定时：在 [base,end) 内做字节模式搜索（?? 通配），返回所有命中地址。
    - pattern 缺省时：扫描 x86/x64 函数序言签名（push rbp;mov rbp,rsp、push ebp;mov ebp,esp、
      push rbx;sub rsp、mov [rsp+XX],rbx、sub rsp,imm8），另加对齐启发
      （4/16 字节对齐且前一字节是 C3/C2/EB/E9），每条结果标注命中的签名名。
    范围上限 16MB。启发式结果可能有误报，需结合反汇编确认。
    """
    if ida_bytes is None:
        return _ida_unavailable()
    if max_results < 1 or max_results > 4096:
        return {"error": "max_results out of range (1..4096)"}

    b, e, err = _parse_range(base, end, MAX_SCAN_RANGE)
    if err:
        return err

    result: dict = {
        "base": hex_addr(b),
        "end": hex_addr(e),
        "size": e - b,
    }

    if pattern and pattern.strip():
        # ---- 字节模式搜索（?? 通配），与 find_bytes 同款 ida_search.find_binary ----
        parts: List[str] = []
        for p in pattern.strip().split():
            if p in ("??", "?"):
                parts.append("?")
            else:
                try:
                    int(p, 16)
                    parts.append(p.upper())
                except ValueError:
                    return {"error": f"invalid hex byte: {p}"}
        if not parts:
            return {"error": "empty pattern after parsing"}
        if ida_search is None or idaapi is None:
            return _ida_unavailable()

        ida_pattern = " ".join(parts)
        matches: List[dict] = []
        ea = b
        while ea < e and len(matches) < max_results:
            try:
                found = ida_search.find_binary(
                    ea, e, ida_pattern, 16,
                    ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT,
                )
            except Exception as ex:
                return {"error": f"search failed: {ex}"}
            if found == idaapi.BADADDR:
                break
            raw = ida_bytes.get_bytes(found, len(parts))
            matches.append({
                "ea": hex_addr(found),
                "bytes": " ".join(f"{x:02X}" for x in raw) if raw else None,
            })
            ea = found + 1

        result.update({
            "mode": "pattern",
            "pattern": ida_pattern,
            "matches": matches,
            "count": len(matches),
            "truncated": len(matches) >= max_results,
        })
        return result

    # ---- 序言签名 + 对齐启发 ----
    data = _read_range(b, e - b)
    if data is None:
        return {"error": "failed to read range", "base": hex_addr(b), "size": e - b}

    hits = _match_prologues(data)
    truncated = len(hits) > max_results
    hits = hits[:max_results]

    result.update({
        "mode": "prologue",
        "signatures": [name for name, _ in _PROLOGUE_SIGNATURES],
        "matches": [
            {
                "ea": hex_addr(b + h["offset"]),
                "signature": h["signature"],
                "bytes": h["bytes"],
            }
            for h in hits
        ],
        "count": len(hits),
        "truncated": truncated,
        "note": "heuristic results; verify with disassembly",
    })
    return result


# ============================================================================
# 编码跳转槽懒解析检测
# ============================================================================

@tool
@idaread
def resolve_jump_slots(
    base: Annotated[Union[int, str], "Range start address"],
    end: Annotated[Union[int, str], "Range end address (exclusive)"],
    ptr_size: Annotated[int, "Pointer size in bytes: 4 or 8"] = 8,
    max_results: Annotated[int, "Max results per category (1..4096)"] = 256,
) -> dict:
    """Classify aligned pointer slots in a region to detect encoded jump slots awaiting lazy resolution (heuristic).

    场景：动态翻译壳的跳转槽常先存编码值，首次跳转时才懒解析为真实代码地址。
    扫描 [base,end) 内按 ptr_size 对齐的槽位，读指针值并分类：
    - resolved:   指向可执行段（getseg 且 SEGPERM_EXEC）
    - internal:   落在 [base,end) 内（缓存内部指针）
    - suspicious: 指向未映射/数据段（可能是待懒解析的编码槽）
    纯启发式，suspicious 项需人工确认。
    """
    if ida_bytes is None or ida_segment is None:
        return _ida_unavailable()
    if ptr_size not in (4, 8):
        return {"error": "ptr_size must be 4 or 8"}
    if max_results < 1 or max_results > 4096:
        return {"error": "max_results out of range (1..4096)"}

    b, e, err = _parse_range(base, end, MAX_SCAN_RANGE)
    if err:
        return err

    data = _read_range(b, e - b)
    if data is None:
        return {"error": "failed to read range", "base": hex_addr(b), "size": e - b}

    big = _is_big_endian()
    resolved: List[dict] = []
    internal: List[dict] = []
    suspicious: List[dict] = []
    skipped_zero = 0
    truncated = False

    for slot, value in _slot_values(data, b, ptr_size, big):
        if value == 0:
            skipped_zero += 1
            continue

        if b <= value < e:
            category = internal
        else:
            seg = ida_segment.getseg(value)
            if seg is not None and (seg.perm & ida_segment.SEGPERM_EXEC):
                category = resolved
            else:
                category = suspicious

        if len(category) < max_results:
            category.append({"slot": hex_addr(slot), "value": hex_addr(value)})
        else:
            truncated = True

    return {
        "base": hex_addr(b),
        "end": hex_addr(e),
        "ptr_size": ptr_size,
        "resolved": resolved,
        "internal": internal,
        "suspicious": suspicious,
        "counts": {
            "resolved": len(resolved),
            "internal": len(internal),
            "suspicious": len(suspicious),
            "skipped_zero": skipped_zero,
        },
        "truncated": truncated,
        "note": "heuristic classification; suspicious entries may be encoded slots awaiting lazy resolution - verify manually",
    }


# ============================================================================
# 全缓存引用扫描
# ============================================================================

@tool
@idaread
def find_refs_in_range(
    base: Annotated[Union[int, str], "Scan range start address"],
    end: Annotated[Union[int, str], "Scan range end address (exclusive)"],
    target_start: Annotated[Union[int, str], "Target range start address"],
    target_end: Annotated[Union[int, str], "Target range end address (exclusive)"],
    ptr_size: Annotated[int, "Pointer size in bytes: 4 or 8"] = 8,
    max_results: Annotated[int, "Max results (1..8192)"] = 512,
) -> dict:
    """Scan every aligned pointer slot in [base,end) for values pointing into [target_start,target_end) - decision-point discovery in a translation cache.

    场景：在整个翻译缓存里找"谁引用了这段代码/数据"，用于判定点发现。
    按 ptr_size 对齐遍历槽位，值落在目标范围内即记录
    {slot, value, offset_into_target}。扫描范围上限 64MB。
    """
    if ida_bytes is None:
        return _ida_unavailable()
    if ptr_size not in (4, 8):
        return {"error": "ptr_size must be 4 or 8"}
    if max_results < 1 or max_results > 8192:
        return {"error": "max_results out of range (1..8192)"}

    b, e, err = _parse_range(base, end, MAX_REF_RANGE)
    if err:
        return err
    ts, te, err = _parse_range(target_start, target_end, MAX_REF_RANGE)
    if err:
        return err

    data = _read_range(b, e - b)
    if data is None:
        return {"error": "failed to read range", "base": hex_addr(b), "size": e - b}

    big = _is_big_endian()
    refs: List[dict] = []
    total = 0
    for slot, value in _slot_values(data, b, ptr_size, big):
        if ts <= value < te:
            total += 1
            if len(refs) < max_results:
                refs.append({
                    "slot": hex_addr(slot),
                    "value": hex_addr(value),
                    "offset_into_target": hex_addr(value - ts),
                })

    return {
        "base": hex_addr(b),
        "end": hex_addr(e),
        "target_start": hex_addr(ts),
        "target_end": hex_addr(te),
        "ptr_size": ptr_size,
        "refs": refs,
        "count": len(refs),
        "total": total,
        "truncated": total > max_results,
    }


# ============================================================================
# 两段内存 / 两个 dump 对比
# ============================================================================

def _load_source(source: Union[int, str], size: int) -> Tuple[Optional[bytes], dict]:
    """加载对比源：IDB 地址（hex 字符串/int）或磁盘 dump 文件路径。

    Returns:
        (data, info)；data 为 None 时 info 含 error
    """
    # 磁盘文件优先（路径存在即按文件处理）
    if isinstance(source, str) and os.path.exists(source):
        try:
            with open(source, "rb") as f:
                data = f.read(size) if size > 0 else f.read()
        except Exception as ex:
            return None, {"error": f"failed to read file: {ex}", "source": source}
        return data, {"type": "file", "source": source, "length": len(data)}

    # 否则按 IDB 地址处理
    parsed = parse_address(source)
    if not parsed["ok"] or parsed["value"] is None:
        return None, {"error": "source is neither an existing file nor a valid address", "source": source}
    if size <= 0:
        return None, {"error": "size is required (> 0) for IDB address sources", "source": source}
    if size > MAX_SCAN_RANGE:
        return None, {"error": f"size too large (max {MAX_SCAN_RANGE} bytes)", "size": size}
    if ida_bytes is None:
        return None, _ida_unavailable()

    data = _read_range(parsed["value"], size)
    if data is None:
        return None, {"error": "failed to read IDB memory", "source": hex_addr(parsed["value"]), "size": size}
    return data, {
        "type": "idb",
        "source": hex_addr(parsed["value"]),
        "length": len(data),
    }


@tool
@idaread
def diff_regions(
    source_a: Annotated[Union[int, str], "IDB address (hex string, size required) or dump file path"],
    source_b: Annotated[Union[int, str], "IDB address (hex string, size required) or dump file path"],
    size: Annotated[int, "Bytes to compare; required (<=16MB) for IDB address sources, 0 = whole file for file sources"] = 0,
    max_runs: Annotated[int, "Max diff runs to return (1..4096)"] = 128,
) -> dict:
    """Compare two dumps or two memory regions (cmp as an MCP tool): diff byte runs with offsets and hex previews.

    场景：两个 dump 对比（如缓存打补丁前后、两次 dump 的差异定位）。
    source_a/source_b 各自可以是 IDB 地址（hex 字符串如 "0x401000"，此时 size 必填）
    或磁盘 dump 文件路径（size=0 表示全文件；两文件长度不同按较短者比并在结果注明）。
    连续不同字节合并为 run，run 数超 max_runs 截断；每 run 的 a_hex/b_hex 最多展示 32 字节。
    """
    if max_runs < 1 or max_runs > 4096:
        return {"error": "max_runs out of range (1..4096)"}

    data_a, info_a = _load_source(source_a, size)
    if data_a is None:
        return {"error": info_a.get("error"), "source_a": info_a}
    data_b, info_b = _load_source(source_b, size)
    if data_b is None:
        return {"error": info_b.get("error"), "source_a": info_a, "source_b": info_b}

    diff = _diff_bytes(data_a, data_b, max_runs=max_runs)

    result: dict = {
        "source_a": info_a,
        "source_b": info_b,
        "compared": min(len(data_a), len(data_b)),
    }
    result.update(diff)
    if len(data_a) != len(data_b):
        result["note"] = "source lengths differ; compared the shorter length"
    return result
