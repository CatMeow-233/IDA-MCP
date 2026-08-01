"""Dump API - 把运行时内存 dump 载入 IDB 并就地分析.

Provides tools:
    - load_memory_dump   本地 dump 文件载入 IDB 为临时段
    - dump_process       从活动进程读内存并载入 IDB（unsafe）
    - analyze_dump       load → 找入口 → force code → disasm 一站式编排

壳分析 80% 是运行时内存：unpacker dump、JIT 缓冲、手动映射的 PE 都不在原始
输入文件里。本模块补上"把 dump 载入 IDB"的缺口。

注意：三个 @tool 函数共享无装饰器的内部实现（_load_dump_impl /
_read_process_memory），避免 @idawrite 的 execute_sync 嵌套调用。
"""
from __future__ import annotations

import os
import sys
from typing import Annotated, Any, Dict, List, Optional, Tuple, Union

from .rpc import tool, unsafe
from .sync import idawrite
from .utils import parse_address, hex_addr
from . import codeforce

# IDA module imports（允许在无 IDA 环境 import 供单元测试）
try:
    import ida_bytes  # type: ignore
    import ida_segment  # type: ignore
except ImportError:
    ida_bytes = None
    ida_segment = None

_MAX_DUMP_FILE = 64 * 1024 * 1024    # 单文件上限 64MB
_MAX_RANGE = 64 * 1024 * 1024        # 单段进程内存上限 64MB
_MAX_TOTAL = 256 * 1024 * 1024       # dump_process 总量上限 256MB
_BITNESS_MAP = {16: 0, 32: 1, 64: 2}
_DEFAULT_PAGE = 0x1000               # 裸地址范围的默认大小

# x86/x64 常见函数序言，用于入口启发式
_PROLOGUES: List[Tuple[bytes, str]] = [
    (bytes.fromhex("554889E5"), "prologue_x64"),      # push rbp; mov rbp, rsp
    (bytes.fromhex("40534883EC"), "prologue_x64_sub"),  # push rbx; sub rsp, imm8
    (bytes.fromhex("558BEC"), "prologue_x86"),        # push ebp; mov ebp, esp
]


# ============================================================================
# 纯逻辑（无 IDA 依赖，可单测）
# ============================================================================

def _parse_ranges(ranges: Union[str, List[Any]]) -> Dict[str, Any]:
    """解析内存范围规格为 [(start, end), ...]。

    支持：
        - "0x7f0000-0x7f2000"     起止区间
        - "0x800000+0x1000"       起点+大小
        - "0x9000"                裸地址 = 一个 4KB 页
        - 逗号分隔组合，或以上形式的列表
    """
    items: List[str]
    if isinstance(ranges, str):
        items = [s.strip() for s in ranges.split(",") if s.strip()]
    elif isinstance(ranges, list):
        items = [str(s).strip() for s in ranges if str(s).strip()]
    else:
        return {"ok": False, "error": "ranges must be a string or list"}

    if not items:
        return {"ok": False, "error": "no ranges given"}

    out: List[Tuple[int, int]] = []
    for item in items:
        if "-" in item:
            start_s, _, end_s = item.partition("-")
            p_start = parse_address(start_s.strip())
            p_end = parse_address(end_s.strip())
            if not p_start["ok"] or not p_end["ok"] or p_start["value"] is None or p_end["value"] is None:
                return {"ok": False, "error": f"invalid range: {item!r}"}
            start, end = p_start["value"], p_end["value"]
        elif "+" in item:
            start_s, _, size_s = item.partition("+")
            p_start = parse_address(start_s.strip())
            p_size = parse_address(size_s.strip())
            if not p_start["ok"] or not p_size["ok"] or p_start["value"] is None or p_size["value"] is None:
                return {"ok": False, "error": f"invalid range: {item!r}"}
            start, end = p_start["value"], p_start["value"] + p_size["value"]
        else:
            p_start = parse_address(item)
            if not p_start["ok"] or p_start["value"] is None:
                return {"ok": False, "error": f"invalid address: {item!r}"}
            start, end = p_start["value"], p_start["value"] + _DEFAULT_PAGE

        if end <= start:
            return {"ok": False, "error": f"range end <= start: {item!r}"}
        out.append((start, end))

    return {"ok": True, "ranges": out}


def _find_entry_candidates(data: bytes, base: int = 0, max_candidates: int = 5) -> List[Dict[str, Any]]:
    """在 dump 字节中找可能的代码入口。

    优先 MZ / ELF magic（offset 0）；否则扫描 x86/x64 函数序言，
    按出现顺序取前 max_candidates 个。返回 [{offset, address, kind}, ...]。
    """
    cands: List[Dict[str, Any]] = []

    if data[:2] == b"MZ":
        cands.append({"offset": 0, "address": hex_addr(base), "kind": "pe"})
        return cands
    if data[:4] == b"\x7fELF":
        cands.append({"offset": 0, "address": hex_addr(base), "kind": "elf"})
        return cands

    hits: List[Tuple[int, str]] = []
    for pattern, kind in _PROLOGUES:
        pos = 0
        while True:
            idx = data.find(pattern, pos)
            if idx < 0:
                break
            hits.append((idx, kind))
            pos = idx + 1
    hits.sort(key=lambda h: h[0])
    seen = set()
    for idx, kind in hits:
        if idx in seen:
            continue
        seen.add(idx)
        cands.append({"offset": idx, "address": hex_addr(base + idx), "kind": kind})
        if len(cands) >= max_candidates:
            break
    return cands


# ============================================================================
# 内部实现（无装饰器，供工具函数与 analyze_dump 复用）
# ============================================================================

def _load_dump_impl(
    data: bytes,
    base: int,
    name: str,
    perm: str,
    bitness: int,
    seg_class: str,
) -> Dict[str, Any]:
    """在 IDB 建临时段并写入 dump 字节。必须在 IDA 主线程调用。"""
    if ida_segment is None or ida_bytes is None:
        return {"error": "IDA SDK not available (not running in IDA?)"}
    if not data:
        return {"error": "no data to load"}
    if bitness not in _BITNESS_MAP:
        return {"error": "bitness must be 16, 32, or 64"}
    if ida_segment.getseg(base):
        return {"error": "base address already belongs to a segment", "base": hex_addr(base)}

    perm_val = 0
    if "r" in perm:
        perm_val |= ida_segment.SEGPERM_READ
    if "w" in perm:
        perm_val |= ida_segment.SEGPERM_WRITE
    if "x" in perm:
        perm_val |= ida_segment.SEGPERM_EXEC

    seg = ida_segment.segment_t()
    seg.start_ea = base
    seg.end_ea = base + len(data)
    seg.perm = perm_val
    seg.bitness = _BITNESS_MAP[bitness]

    if not ida_segment.add_segm_ex(seg, name, seg_class, 0):
        return {
            "error": "add_segm_ex failed",
            "base": hex_addr(base),
            "size": len(data),
            "name": name,
        }

    ida_bytes.put_bytes(base, data)

    return {
        "name": name,
        "start_ea": hex_addr(base),
        "end_ea": hex_addr(base + len(data)),
        "size": len(data),
        "class": seg_class,
        "perm": perm,
        "bitness": bitness,
    }


def _read_dump_file(file: str, size: int) -> Tuple[Optional[bytes], Optional[str]]:
    """读本地 dump 文件；size=0 表示全文件。返回 (data, error)。"""
    if size < 0:
        return None, "size must be >= 0"
    try:
        file_size = os.path.getsize(file)
    except OSError as e:
        return None, f"cannot stat file: {e}"
    if size == 0 and file_size > _MAX_DUMP_FILE:
        return None, f"file too large ({file_size} bytes, max {_MAX_DUMP_FILE})"
    if size > _MAX_DUMP_FILE:
        return None, f"size too large (max {_MAX_DUMP_FILE})"
    try:
        with open(file, "rb") as f:
            data = f.read(size if size > 0 else -1)
    except OSError as e:
        return None, f"cannot read file: {e}"
    if not data:
        return None, "file is empty"
    return data, None


def _read_process_memory(pid: int, start: int, size: int) -> Tuple[Optional[bytes], Optional[str]]:
    """从活动进程读 size 字节。Windows 用 ReadProcessMemory，Linux 读 /proc/pid/mem。"""
    if sys.platform.startswith("win"):
        import ctypes

        PROCESS_VM_READ = 0x0010
        PROCESS_QUERY_INFORMATION = 0x0400
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        kernel32.ReadProcessMemory.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
        ]
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]

        handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            return None, f"OpenProcess failed (pid={pid}); need PROCESS_VM_READ access"
        try:
            buf = ctypes.create_string_buffer(size)
            nread = ctypes.c_size_t(0)
            ok = kernel32.ReadProcessMemory(handle, ctypes.c_void_p(start), buf, size, ctypes.byref(nread))
            if not ok or nread.value == 0:
                return None, f"ReadProcessMemory failed at {hex_addr(start)} (size=0x{size:X})"
            return buf.raw[: nread.value], None
        finally:
            kernel32.CloseHandle(handle)

    if sys.platform.startswith("linux"):
        path = f"/proc/{pid}/mem"
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError as e:
            return None, f"open {path} failed: {e}"
        try:
            data = os.pread(fd, size, start)
            if not data:
                return None, f"pread returned 0 bytes at {hex_addr(start)}"
            return data, None
        except OSError as e:
            return None, f"pread {path} failed at {hex_addr(start)}: {e}"
        finally:
            os.close(fd)

    return None, f"unsupported platform: {sys.platform}"


# ============================================================================
# Tools
# ============================================================================

@tool
@idawrite
def load_memory_dump(
    file: Annotated[str, "Local dump file path (on the machine running IDA)"],
    base: Annotated[Union[int, str], "Base address to load the dump at (hex or decimal)"],
    size: Annotated[int, "Bytes to read from file; 0 = whole file (max 64MB)"] = 0,
    name: Annotated[Optional[str], "Segment name; defaults to the file name"] = None,
    perm: Annotated[str, "Permission string: combination of r/w/x (e.g. 'rwx', 'r-x')"] = "rwx",
    bitness: Annotated[int, "Address size: 16, 32, or 64"] = 64,
    seg_class: Annotated[str, "Segment class (e.g. 'CODE', 'DATA')"] = "CODE",
) -> dict:
    """Load a local memory-dump file into the IDB as a temporary segment — the missing piece for shell/unpacked-code analysis where 80% of the code only exists at runtime.

    适用于 unpacker dump、手动映射 PE、JIT 缓冲等不在输入文件里的代码。
    base 已被段占用时返回 error。载入后建议接着用 analyze_dump 做入口探测 +
    强制解码，或对目标区域 force-code 后用 disasm_text / decompile。
    """
    parsed = parse_address(base)
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid base address"}

    data, err = _read_dump_file(file, size)
    if err:
        return {"error": err, "file": file}

    seg_name = name or os.path.basename(file)
    result = _load_dump_impl(data, parsed["value"], seg_name, perm, bitness, seg_class)
    if "error" in result:
        return result

    result["file"] = file
    result["hint"] = (
        "dump 已载入为新段。下一步: analyze_dump(file, base) 做入口探测+强制解码, "
        "或对入口区域 force-code 后用 disasm_text / decompile 分析。"
    )
    return result


@tool
@unsafe
@idawrite
def dump_process(
    pid: Annotated[int, "Target process ID to read memory from"],
    ranges: Annotated[Union[str, List[Any]], "Memory ranges: '0x7f0000-0x7f2000,0x800000+0x1000' or list; bare address = one 4KB page"],
    perm: Annotated[str, "Permission string for created segments: combination of r/w/x"] = "rwx",
) -> dict:
    """Read memory ranges from a live process and load them into the IDB — for dumping injected/unpacked code straight out of a running target (unsafe: touches another process).

    Windows 用 OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION) +
    ReadProcessMemory；Linux 回退读 /proc/pid/mem；其他平台报 error。
    单段上限 64MB，总量上限 256MB；单段读失败不致命，记入 failed_ranges。
    成功段名为 f"pid{pid}_{start:x}"，之后可用 analyze/disasm 工具分析。
    """
    if ida_segment is None or ida_bytes is None:
        return {"error": "IDA SDK not available (not running in IDA?)"}

    parsed_ranges = _parse_ranges(ranges)
    if not parsed_ranges["ok"]:
        return {"error": parsed_ranges["error"]}

    loaded: List[dict] = []
    failed: List[dict] = []
    total = 0

    for start, end in parsed_ranges["ranges"]:
        size = end - start
        if size > _MAX_RANGE:
            failed.append({"range": f"{hex_addr(start)}-{hex_addr(end)}", "error": f"range too large (max {_MAX_RANGE})"})
            continue
        if total + size > _MAX_TOTAL:
            failed.append({"range": f"{hex_addr(start)}-{hex_addr(end)}", "error": f"total limit exceeded (max {_MAX_TOTAL})"})
            continue

        data, err = _read_process_memory(pid, start, size)
        if err:
            failed.append({"range": f"{hex_addr(start)}-{hex_addr(end)}", "error": err})
            continue

        seg_name = f"pid{pid}_{start:x}"
        result = _load_dump_impl(data, start, seg_name, perm, 64, "CODE")
        if "error" in result:
            failed.append({"range": f"{hex_addr(start)}-{hex_addr(end)}", "error": result["error"]})
            continue
        total += len(data)
        loaded.append(result)

    return {
        "pid": pid,
        "loaded": loaded,
        "failed_ranges": failed,
        "total_bytes": total,
        "hint": "成功段已载入 IDB。下一步: 对入口区域 force-code 后用 disasm_text / decompile, 或 emu_run 直接仿真。",
    }


@tool
@idawrite
def analyze_dump(
    file: Annotated[str, "Local dump file path (on the machine running IDA)"],
    base: Annotated[Union[int, str], "Base address to load the dump at (hex or decimal)"],
    entry: Annotated[Optional[Union[int, str]], "Entry address/offset hint; omit to auto-detect via MZ/ELF magic or x86 prologue scan"] = None,
    bitness: Annotated[int, "Address size: 16, 32, or 64"] = 64,
) -> dict:
    """One-call dump workflow: load dump → find entry → force code → disasm → report — saves the LLM several round-trips when triaging shellcode/unpacked blobs.

    步骤: 载入 dump 建段(rwx/CODE) → entry 未给时做入口启发式(MZ/ELF magic,
    否则扫 55 48 89 E5 / 40 53 48 83 EC / 55 8B EC 序言) → 对入口起 4KB(或全段
    中较小者) force_code_range 强制解码 → capstone 反汇编入口起最多 100 条指令。
    返回 {segment, entry_candidates, forced, disasm_preview, hints}。
    """
    parsed = parse_address(base)
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid base address"}
    base_ea = parsed["value"]

    data, err = _read_dump_file(file, 0)
    if err:
        return {"error": err, "file": file}

    seg_name = os.path.basename(file)
    segment = _load_dump_impl(data, base_ea, seg_name, "rwx", bitness, "CODE")
    if "error" in segment:
        return segment

    # 1) 入口确定：显式 entry 优先，否则启发式
    candidates = _find_entry_candidates(data, base_ea)
    if entry is not None:
        p_entry = parse_address(entry)
        if not p_entry["ok"] or p_entry["value"] is None:
            return {"error": "invalid entry address", "segment": segment}
        entry_val = p_entry["value"]
        # 允许传段内偏移（小于段大小）或绝对地址
        entry_ea = base_ea + entry_val if entry_val < len(data) else entry_val
        entry_kind = "explicit"
    elif candidates:
        entry_ea = base_ea + candidates[0]["offset"]
        entry_kind = candidates[0]["kind"]
    else:
        entry_ea = base_ea
        entry_kind = "segment_base"

    entry_off = entry_ea - base_ea
    if entry_off < 0 or entry_off >= len(data):
        return {
            "error": "entry is outside the loaded segment",
            "segment": segment,
            "entry": hex_addr(entry_ea),
        }

    # 2) 强制解码入口所在区域（4KB 或全段中较小者）
    force_start = entry_ea
    force_end = min(entry_ea + 0x1000, base_ea + len(data))
    forced = codeforce.force_code_range(force_start, force_end)
    forced_result: Dict[str, Any] = {
        "start": hex_addr(force_start),
        "end": hex_addr(force_end),
        "result": forced,
    }

    # 3) capstone 反汇编预览（不依赖 IDB 解码结果）。
    #    优先用 IDB 架构（dump 与当前目标同平台的场景占绝大多数，
    #    T盾/壳 dump 均为 ARM64）；仅在检测失败时按 bitness 兜底 x86 系。
    arch = codeforce._detect_arch()
    if arch not in ("x64", "x86", "arm64", "arm"):
        arch = "x64" if bitness == 64 else "x86"
    disasm = codeforce.capstone_disasm_range(
        entry_ea, data[entry_off:entry_off + 0x1000], arch=arch, max_instructions=100
    )
    preview = disasm.get("instructions", []) if "error" not in disasm else []
    disasm_error = disasm.get("error")
    preview_arch = arch

    report: Dict[str, Any] = {
        "segment": segment,
        "entry": hex_addr(entry_ea),
        "entry_kind": entry_kind,
        "entry_candidates": candidates,
        "forced": forced_result,
        "disasm_preview": preview,
        "preview_arch": preview_arch,
        "hints": [
            f"入口区域已强制解码: disasm_text('{hex_addr(entry_ea)}') 或 decompile 查看伪代码。",
            "若 preview 像垃圾代码，换 entry_candidates 里的其他候选重试（entry 参数）。",
            "动态行为可用 emu_run(start=入口) 直接仿真该段。",
        ],
    }
    if disasm_error:
        report["disasm_error"] = disasm_error
    return report
