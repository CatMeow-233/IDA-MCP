"""Compress API - SEMZ v1 semantic compression of disassembly.

Provides tools:
    - compress_function   compress a function into SEMZ DSL text
    - compress_range      compress an address range into SEMZ DSL text
    - compress_text       compress raw assembly/trace text into SEMZ DSL text
    - extract_block       extract specific blocks (by Ln label) from a function
    - disasm_text         raw IDA disassembly as plain text (no SEMZ encoding)
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from typing import Annotated, List, Optional, Union

from .rpc import tool
from .sync import idaread, wait_for_auto_analysis
from .utils import parse_address, hex_addr
from .compress import (
    compress_insns as _compress_insns,
    compress_text as _compress_text,
    extract_blocks as _extract_blocks,
    format_blocks as _format_blocks,
    CompressError,
)

# IDA module imports
try:
    import idaapi  # type: ignore
    import ida_ida  # type: ignore
    import idautils  # type: ignore
    import ida_xref  # type: ignore
except ImportError:
    # allow import outside IDA (e.g. for tests), but related features will be unavailable
    idaapi = None
    ida_ida = None
    idautils = None
    ida_xref = None

_LEVELS = ("safe", "full", "max", "ultra")
_MAX_OUTPUT = 120_000

_HINT = (
    "SEMZ is compressed disassembly for scanning/transfer. "
    "Use decompile for semantics on normal code; on obfuscated code (VMP/OLLVM) "
    "decompiler output may fail or mislead — trust the disassembly level (disasm/SEMZ). "
    "Need raw disassembly text without SEMZ decoding: use disasm_text. "
    "Decode manual: MCP resource ida://semz/manual or instructor/LLM_INSTRUCTOR.md."
)


def _detect_arch() -> str:
    """从当前 IDB 判定目标架构（SPEC §5e）。

    IDA 9 优先走 `ida_ida.inf_get_procname()` / `ida_ida.inf_is_64bit()`：
    procname 含 "ARM" → "arm64"；否则按位宽 "x64"/"x86"。
    旧版回退 `idaapi.get_inf_structure()`；最终回退 "auto"。
    """
    procname: Optional[str] = None
    is64: Optional[bool] = None

    if ida_ida is not None:
        try:
            raw = ida_ida.inf_get_procname()
            if isinstance(raw, bytes):
                raw = raw.decode(errors="ignore")
            procname = raw or None
        except Exception:
            pass
        try:
            is64 = bool(ida_ida.inf_is_64bit())
        except Exception:
            pass

    if procname is None and is64 is None and idaapi is not None:
        try:
            inf = idaapi.get_inf_structure()
            procname = str(inf.procname) if inf.procname else None
            is64 = bool(inf.is_64bit())
        except Exception:
            pass

    if procname and "ARM" in procname.upper():
        return "arm64"
    if is64 is not None:
        return "x64" if is64 else "x86"
    return "auto"


def _make_jt_resolver():
    """构造基于 IDA 交叉引用的跳转表目标解析器（压缩管线为纯计算，目标在此注入）。

    优先取 fl_JN/fl_JF 跳转 xref（switch case）；无结果时取其余代码 xref
    （排除普通流 fl_F 与调用 fl_CN/fl_CF）。
    """
    if idautils is None or ida_xref is None:
        return None

    def resolve(ea: int):
        try:
            jumps: List[int] = []
            others: List[int] = []
            for xb in idautils.XrefsFrom(ea):
                target = int(getattr(xb, "to", 0) or 0)
                if not target:
                    continue
                xtype = getattr(xb, "type", None)
                if xtype in (ida_xref.fl_JN, ida_xref.fl_JF):
                    jumps.append(target)
                elif (
                    xtype not in (ida_xref.fl_F, ida_xref.fl_CN, ida_xref.fl_CF)
                    and getattr(xb, "iscode", 0)
                ):
                    others.append(target)
            seen: List[int] = []
            for target in jumps or others:
                if target not in seen:
                    seen.append(target)
            return seen or None
        except Exception:
            return None

    return resolve


_MACRO_DEF_RE = re.compile(r"^#P (P\d+)=(.*)$")
_MACRO_REF_RE = re.compile(r"P\d+")


def _expand_macros(text: str) -> str:
    """内联展开 #P 序列宏（expand_macros=true 时）。

    宏体可引用先定义的宏，迭代展开直至无 Pn 引用残留；#P 定义行移除，
    其余头部（#SZ1/#K/#J/#f）保留。
    """
    macros: dict = {}
    kept: List[str] = []
    for ln in text.splitlines():
        m = _MACRO_DEF_RE.match(ln)
        if m:
            macros[m.group(1)] = m.group(2).split(";")
        else:
            kept.append(ln)
    if not macros:
        return text
    for _ in range(16):
        refs = [
            i for i, ln in enumerate(kept)
            if _MACRO_REF_RE.fullmatch(ln.strip()) and ln.strip() in macros
        ]
        if not refs:
            break
        for i in reversed(refs):
            kept[i:i + 1] = macros[kept[i].strip()]
    return "\n".join(kept) + "\n"


def _resolve_macro_lines(macros: dict) -> dict:
    """把每个宏体迭代解析为纯指令序列（嵌套引用展开，上限 16 轮）。"""
    resolved = {name: list(body) for name, body in macros.items()}
    for _ in range(16):
        changed = False
        for name in resolved:
            out: List[str] = []
            for ln in resolved[name]:
                s = ln.strip()
                if _MACRO_REF_RE.fullmatch(s) and s in resolved:
                    out.extend(resolved[s])
                    changed = True
                else:
                    out.append(ln)
            resolved[name] = out
        if not changed:
            break
    return resolved


def _annotate_macros(text: str) -> str:
    """annotate 模式：保留 #P 定义/引用行，在宏引用行尾追加展开注释。

    形如 `P0  ; = <insn>; <insn>; ...`；宏体嵌套引用先迭代解析为纯指令序列。
    """
    macros: dict = {}
    for ln in text.splitlines():
        m = _MACRO_DEF_RE.match(ln)
        if m:
            macros[m.group(1)] = m.group(2).split(";")
    if not macros:
        return text
    resolved = _resolve_macro_lines(macros)
    out: List[str] = []
    for ln in text.splitlines():
        s = ln.strip()
        if _MACRO_REF_RE.fullmatch(s) and s in resolved:
            out.append(f"{ln}  ; = {'; '.join(resolved[s])}")
        else:
            out.append(ln)
    return "\n".join(out) + "\n"


def _apply_macro_mode(text: str, expand_macros) -> str:
    """expand_macros=False 原样 / True 全展开 / "annotate" 引用行尾注释。"""
    if expand_macros == "annotate":
        return _annotate_macros(text)
    if expand_macros:
        return _expand_macros(text)
    return text


def _collect_heads(start: int, end: int) -> List[dict]:
    """idautils.Heads + generate_disasm_line 取 {ea,text,comment}（对齐 api_analysis.disasm 模式）。"""
    instructions: List[dict] = []
    for head_ea in idautils.Heads(start, end):
        try:
            flags = idaapi.get_full_flags(head_ea)
            if not idaapi.is_code(flags):
                continue
            text: Optional[str] = None
            try:
                text = idaapi.generate_disasm_line(head_ea, 0)
            except Exception:
                text = None
            if text is None:
                text = "?"
            cmt_parts: List[str] = []
            try:
                c1 = idaapi.get_cmt(head_ea, False)
                if c1:
                    cmt_parts.append(c1)
            except Exception:
                pass
            try:
                c2 = idaapi.get_cmt(head_ea, True)
                if c2:
                    cmt_parts.append(c2)
            except Exception:
                pass
            instructions.append({
                "ea": int(head_ea),
                "text": text,
                "comment": " // ".join(cmt_parts) if cmt_parts else None,
            })
        except Exception:
            continue
    return instructions


def _map_payload(result: dict) -> dict:
    """管线 map（[(label, ea), ...]）→ {label: "0x..."} 字典（ea 缺失的跳过）。"""
    out: dict = {}
    for label, ea in result.get("map") or []:
        if ea is not None:
            out[label] = hex_addr(ea)
    return out


def _pack(
    result: dict,
    level: str,
    name: str,
    ea,
    line_offset: int = 0,
    line_limit: Optional[int] = None,
    out_file: Optional[str] = None,
    expand_macros: Union[bool, str] = False,
    with_map: bool = False,
) -> dict:
    """装配返回：out_file 落盘 > 行分页 > 全文（默认）。

    compressed 恒放最后：客户端对超长响应做显示截断时，stats 等元信息仍可读。
    hint（定位提示）随响应返回，写在 compressed 之前；不落盘、不拼进文本。
    落盘文件是临时产物——调用方应在任务结束经用户确认后删除。
    expand_macros=true 时 #P 宏全部内联展开（stats 仍描述压缩形态）；
    expand_macros="annotate" 时保留宏并在引用行尾追加展开注释。
    with_map=true 时附带 Ln 标签 → 块首地址映射（落盘时写 <out_file>.map.json）。
    """
    text = result["text"]
    text = _apply_macro_mode(text, expand_macros)
    stats = result["stats"]
    payload: dict = {
        "name": name,
        "ea": ea,
        "level": level,
        "stats": {
            "orig": stats["orig"],
            "out": stats["out"],
            "elim": stats["elim"],
            "ratio": stats["ratio"],
        },
        # 定位提示恒在 compressed 之前（仅随响应返回，不写落盘文件/不拼进文本）
        "hint": _HINT,
    }

    if out_file:
        # 落盘：写全文（不受 _MAX_OUTPUT 截断），不回传 compressed
        path = out_file
        if not os.path.isabs(path):
            path = os.path.join(tempfile.gettempdir(), "ida_mcp_out", path)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        payload["file"] = path
        payload["chars"] = len(text)
        if with_map:
            map_path = path + ".map.json"
            with open(map_path, "w", encoding="utf-8") as f:
                json.dump(_map_payload(result), f, indent=1)
            payload["map_file"] = map_path
        return payload

    if with_map:
        payload["map"] = _map_payload(result)

    if line_limit is not None or line_offset:
        # 分级阅读：按行切片（头部行也在切片范围内，第 0 页即 #SZ1/#K/#P）
        lines = text.splitlines()
        total = len(lines)
        offset = max(0, int(line_offset))
        end = None if line_limit is None else offset + max(1, int(line_limit))
        chunk = lines[offset:end]
        payload["truncated"] = False
        payload["line_offset"] = offset
        payload["line_total"] = total
        payload["compressed"] = "\n".join(chunk) + "\n" if chunk else ""
        return payload

    truncated = False
    if len(text) > _MAX_OUTPUT:
        text = text[:_MAX_OUTPUT]
        truncated = True
    payload["truncated"] = truncated
    payload["compressed"] = text
    return payload


@tool
@idaread
def compress_function(
    query: Annotated[Union[int, str], "Function address or symbol name"],
    level: Annotated[str, "Compression level: safe|full|max|ultra (default)"] = "ultra",
    arch: Annotated[str, "Target architecture: auto (default, from IDB procname)|x86|x64|arm64"] = "auto",
    line_offset: Annotated[int, "Paging: start line of the compressed text (default 0)"] = 0,
    line_limit: Annotated[Optional[int], "Paging: max lines to return; omit for full text"] = None,
    out_file: Annotated[Optional[str], "Write full output to a file instead of returning inline (relative paths go to %TEMP%/ida_mcp_out/)"] = None,
    expand_macros: Annotated[Union[bool, str], "Inline-expand #P sequence macros (true: fully expanded output with no macro definitions/references; 'annotate': keep macros and append an expansion comment on each reference line)"] = False,
    with_map: Annotated[bool, "Include Ln label -> block start address map (inline 'map' field, or <out_file>.map.json sidecar when writing to file)"] = False,
) -> dict:
    """Compress a function's disassembly into SEMZ DSL text — compact for bulk scanning/transfer; also the right choice when decompile fails or misleads on obfuscated code (VMP/OLLVM) (default level: ultra).

    On normal code decompile is fastest for semantics; when decompile fails or
    misleads (obfuscated/virtualized code), trust this disassembly-level view.
    Large output: page with
    line_offset/line_limit, or spill to out_file (delete after user confirms).
    In-function direct branch targets are always rendered as Ln labels.
    """
    if level not in _LEVELS:
        return {"error": f"invalid level (must be one of {_LEVELS})"}
    if idaapi is None:
        return {"error": "IDA SDK not available"}
    wait_for_auto_analysis()

    from .api_analysis import _resolve_function

    info = _resolve_function(query)
    if info.get("error"):
        return info

    instructions = _collect_heads(info["start_ea"], info["end_ea"])
    if not instructions:
        return {"error": "no instructions", "query": query}

    try:
        result = _compress_insns(
            instructions, level=level, name=info["name"] or "?",
            arch=_detect_arch() if arch == "auto" else arch,
            jt_resolver=_make_jt_resolver(),
        )
    except CompressError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"compress failed: {e}"}

    return _pack(result, level, info["name"], hex_addr(info["start_ea"]),
                 line_offset=line_offset, line_limit=line_limit, out_file=out_file,
                 expand_macros=expand_macros, with_map=with_map)


@tool
@idaread
def compress_range(
    start: Annotated[Union[int, str], "Start address"],
    end: Annotated[Union[int, str], "End address (exclusive)"],
    level: Annotated[str, "Compression level: safe|full|max|ultra (default)"] = "ultra",
    arch: Annotated[str, "Target architecture: auto (default, from IDB procname)|x86|x64|arm64"] = "auto",
    line_offset: Annotated[int, "Paging: start line of the compressed text (default 0)"] = 0,
    line_limit: Annotated[Optional[int], "Paging: max lines to return; omit for full text"] = None,
    out_file: Annotated[Optional[str], "Write full output to a file instead of returning inline (relative paths go to %TEMP%/ida_mcp_out/)"] = None,
    expand_macros: Annotated[Union[bool, str], "Inline-expand #P sequence macros (true: fully expanded output with no macro definitions/references; 'annotate': keep macros and append an expansion comment on each reference line)"] = False,
    with_map: Annotated[bool, "Include Ln label -> block start address map (inline 'map' field, or <out_file>.map.json sidecar when writing to file)"] = False,
) -> dict:
    """Linear-disassemble an address range and compress it into SEMZ DSL text — compact for bulk scanning/transfer; reliable when decompile fails or misleads on obfuscated code (VMP/OLLVM) (default level: ultra).

    On normal code decompile is fastest for semantics; when decompile fails or
    misleads (obfuscated/virtualized code), trust this disassembly-level view.
    Large output: page with
    line_offset/line_limit, or spill to out_file (delete after user confirms).
    """
    if level not in _LEVELS:
        return {"error": f"invalid level (must be one of {_LEVELS})"}
    if idaapi is None:
        return {"error": "IDA SDK not available"}
    wait_for_auto_analysis()

    parsed_start = parse_address(start)
    if not parsed_start["ok"] or parsed_start["value"] is None:
        return {"error": "invalid start"}
    parsed_end = parse_address(end)
    if not parsed_end["ok"] or parsed_end["value"] is None:
        return {"error": "invalid end"}

    start_ea = int(parsed_start["value"])
    end_ea = int(parsed_end["value"])
    if end_ea <= start_ea:
        return {"error": "end must be greater than start"}

    instructions = _collect_heads(start_ea, end_ea)
    if not instructions:
        return {"error": "no instructions"}

    name = f"{hex_addr(start_ea)}-{hex_addr(end_ea)}"
    try:
        result = _compress_insns(
            instructions, level=level, name=name,
            arch=_detect_arch() if arch == "auto" else arch,
            jt_resolver=_make_jt_resolver(),
        )
    except CompressError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"compress failed: {e}"}

    return _pack(result, level, name, hex_addr(start_ea),
                 line_offset=line_offset, line_limit=line_limit, out_file=out_file,
                 expand_macros=expand_macros, with_map=with_map)


@tool
def compress_text(
    asm_text: Annotated[str, "Assembly / trace text (IDA export, x64dbg trace, ...)"],
    level: Annotated[str, "Compression level: safe|full|max|ultra (default)"] = "ultra",
    arch: Annotated[str, "Target architecture: auto (default, heuristic)|x86|x64|arm64"] = "auto",
    line_offset: Annotated[int, "Paging: start line of the compressed text (default 0)"] = 0,
    line_limit: Annotated[Optional[int], "Paging: max lines to return; omit for full text"] = None,
    out_file: Annotated[Optional[str], "Write full output to a file instead of returning inline (relative paths go to %TEMP%/ida_mcp_out/)"] = None,
    expand_macros: Annotated[Union[bool, str], "Inline-expand #P sequence macros (true: fully expanded output with no macro definitions/references; 'annotate': keep macros and append an expansion comment on each reference line)"] = False,
    with_map: Annotated[bool, "Include Ln label -> block start address map (inline 'map' field, or <out_file>.map.json sidecar when writing to file)"] = False,
) -> dict:
    """Compress raw assembly or trace text into SEMZ DSL text — compact for bulk scanning/transfer and for inspecting code where decompile fails or misleads (pure computation, no IDA SDK; default level: ultra).

    Large output: page with line_offset/line_limit, or spill to out_file
    (delete after user confirms).
    """
    if level not in _LEVELS:
        return {"error": f"invalid level (must be one of {_LEVELS})"}
    if not isinstance(asm_text, str) or not asm_text.strip():
        return {"error": "empty text"}

    try:
        result = _compress_text(asm_text, level=level, name="text", arch=arch)
    except CompressError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"compress failed: {e}"}

    return _pack(result, level, "text", None,
                 line_offset=line_offset, line_limit=line_limit, out_file=out_file,
                 expand_macros=expand_macros, with_map=with_map)


@tool
@idaread
def extract_block(
    query: Annotated[Union[int, str], "Function address or symbol name"],
    labels: Annotated[Union[str, List[str]], "Block label(s) to extract: \"L7\", \"L7,L8\", or [\"L7\",\"L8\"]"],
    expand_macros: Annotated[Union[bool, str], "Inline-expand #P sequence macros in the returned block text (true: full expansion; 'annotate': keep macros and append expansion comments)"] = False,
) -> dict:
    """Extract specific basic blocks (by Ln label) from a function's SEMZ ultra compression — disassembly-level shards for block analysis when decompile fails or misleads.

    Re-runs the deterministic ultra compression (labels are assigned in address
    order, identical to compress_function output) and returns the header lines
    (#SZ1/#K/#P/#J/#f) plus only the requested blocks' original lines, plus a
    label -> address map for the requested blocks. Use this to prepare
    block-analysis shards instead of hand-cutting the full compressed text.
    """
    if idaapi is None:
        return {"error": "IDA SDK not available"}
    wait_for_auto_analysis()

    if isinstance(labels, str):
        label_list = [lb.strip() for lb in re.split(r"[,\s]+", labels) if lb.strip()]
    else:
        label_list = [str(lb).strip() for lb in labels if str(lb).strip()]
    if not label_list:
        return {"error": "no labels given"}

    from .api_analysis import _resolve_function

    info = _resolve_function(query)
    if info.get("error"):
        return info

    instructions = _collect_heads(info["start_ea"], info["end_ea"])
    if not instructions:
        return {"error": "no instructions", "query": query}

    try:
        result = _compress_insns(
            instructions, level="ultra", name=info["name"] or "?",
            arch=_detect_arch(),
            jt_resolver=_make_jt_resolver(),
        )
    except CompressError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"compress failed: {e}"}

    extracted = _extract_blocks(result["text"], label_list)
    if extracted.get("error"):
        extracted["name"] = info["name"]
        return extracted

    text = _format_blocks(extracted, with_header=True)
    text = _apply_macro_mode(text, expand_macros)
    full_map = _map_payload(result)
    return {
        "name": info["name"],
        "ea": hex_addr(info["start_ea"]),
        "labels": label_list,
        "map": {lb: full_map[lb] for lb in label_list if lb in full_map},
        "text": text,
    }


# ============================================================================
# disasm_text：IDA 原始反汇编纯文本（无 SEMZ 编码）
# ============================================================================

def _format_disasm_lines(instructions: List[dict]) -> str:
    """{ea,text,comment} → `0x<ea>: <text>` 行（有 comment 追加 ` ; <comment>`）。"""
    lines: List[str] = []
    for ins in instructions:
        line = f"{hex_addr(ins['ea'])}: {ins['text']}"
        if ins.get("comment"):
            line += f" ; {ins['comment']}"
        lines.append(line)
    return "\n".join(lines) + "\n"


def _pack_plain(
    text: str,
    name: str,
    ea,
    count: int,
    line_offset: int = 0,
    line_limit: Optional[int] = None,
    out_file: Optional[str] = None,
) -> dict:
    """disasm_text 装配：与 _pack 同约定（out_file 落盘 > 行分页 > 全文）。

    大文本字段 disasm 恒放最后（对齐 compressed 约定：显示截断时元信息仍可读）。
    落盘文件是临时产物——调用方应在任务结束经用户确认后删除。
    """
    payload: dict = {"name": name, "ea": ea, "instructions": count}

    if out_file:
        # 落盘：写全文（不受 _MAX_OUTPUT 截断），不回传 disasm
        path = out_file
        if not os.path.isabs(path):
            path = os.path.join(tempfile.gettempdir(), "ida_mcp_out", path)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        payload["file"] = path
        payload["chars"] = len(text)
        return payload

    if line_limit is not None or line_offset:
        # 分级阅读：按行切片
        lines = text.splitlines()
        total = len(lines)
        offset = max(0, int(line_offset))
        end = None if line_limit is None else offset + max(1, int(line_limit))
        chunk = lines[offset:end]
        payload["truncated"] = False
        payload["line_offset"] = offset
        payload["line_total"] = total
        payload["disasm"] = "\n".join(chunk) + "\n" if chunk else ""
        return payload

    truncated = False
    if len(text) > _MAX_OUTPUT:
        text = text[:_MAX_OUTPUT]
        truncated = True
    payload["truncated"] = truncated
    payload["disasm"] = text
    return payload


@tool
@idaread
def disasm_text(
    query: Annotated[Optional[Union[int, str]], "Function address or symbol name; omit when using start/end"] = None,
    start: Annotated[Optional[Union[int, str]], "Range start address (requires end; ignored when query is given)"] = None,
    end: Annotated[Optional[Union[int, str]], "Range end address (exclusive, requires start)"] = None,
    line_offset: Annotated[int, "Paging: start line of the output text (default 0)"] = 0,
    line_limit: Annotated[Optional[int], "Paging: max lines to return; omit for full text"] = None,
    out_file: Annotated[Optional[str], "Write full output to a file instead of returning inline (relative paths go to %TEMP%/ida_mcp_out/)"] = None,
) -> dict:
    """Return IDA's raw disassembly as plain text — the trusted ground truth on obfuscated/virtualized code (VMP/OLLVM) where decompile fails or misleads; no SEMZ decoding needed.

    One line per instruction: `0x<ea>: <text>` (plus ` ; <comment>` when present),
    exactly as IDA renders it — no SEMZ encoding, readable by any LLM agent.
    On obfuscated code pseudo-C may look plausible while being wrong; trust this
    disassembly-level view. For semantics on normal code decompile is fastest;
    for transfer-size compression use compress_function/compress_range.
    Pass either query (function) or start+end (range). Large output: page with
    line_offset/line_limit, or spill to out_file (delete after user confirms).
    """
    if idaapi is None:
        return {"error": "IDA SDK not available"}
    wait_for_auto_analysis()

    if query is not None:
        from .api_analysis import _resolve_function

        info = _resolve_function(query)
        if info.get("error"):
            return info
        start_ea = info["start_ea"]
        end_ea = info["end_ea"]
        name = info["name"] or "?"
    else:
        if start is None or end is None:
            return {"error": "pass either query (function) or start+end (range)"}
        parsed_start = parse_address(start)
        if not parsed_start["ok"] or parsed_start["value"] is None:
            return {"error": "invalid start"}
        parsed_end = parse_address(end)
        if not parsed_end["ok"] or parsed_end["value"] is None:
            return {"error": "invalid end"}
        start_ea = int(parsed_start["value"])
        end_ea = int(parsed_end["value"])
        if end_ea <= start_ea:
            return {"error": "end must be greater than start"}
        name = f"{hex_addr(start_ea)}-{hex_addr(end_ea)}"

    instructions = _collect_heads(start_ea, end_ea)
    if not instructions:
        return {"error": "no instructions", "query": query} if query is not None else {"error": "no instructions"}

    text = _format_disasm_lines(instructions)
    return _pack_plain(text, name, hex_addr(start_ea), len(instructions),
                       line_offset=line_offset, line_limit=line_limit, out_file=out_file)
