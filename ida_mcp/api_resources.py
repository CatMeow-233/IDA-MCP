"""Read-only MCP resources for stable IDA context snapshots."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .rpc import resource
from .strings_cache import get_strings_cache
from .sync import idaread
from .type_utils import iter_local_type_ordinals
from .utils import hex_addr

try:
    import idaapi  # type: ignore
except ImportError:  # pragma: no cover
    idaapi = None

try:
    import idautils  # type: ignore
except ImportError:  # pragma: no cover
    idautils = None

try:
    import ida_funcs  # type: ignore
except ImportError:  # pragma: no cover
    ida_funcs = None

try:
    import ida_bytes  # type: ignore
except ImportError:  # pragma: no cover
    ida_bytes = None

try:
    import ida_typeinf  # type: ignore
except ImportError:  # pragma: no cover
    ida_typeinf = None

try:
    import ida_segment  # type: ignore
except ImportError:  # pragma: no cover
    ida_segment = None


def _json_resource(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, default=str)


def _resource_error(code: str, message: str, **details: Any) -> str:
    payload: dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
        }
    }
    if details:
        payload["error"]["details"] = details
    return _json_resource(payload)


def _resource_list(kind: str, items: list[dict[str, Any]], **fields: Any) -> str:
    payload: dict[str, Any] = {
        "kind": kind,
        "count": len(items),
        "items": items,
    }
    payload.update(fields)
    return _json_resource(payload)


def _resource_detail(kind: str, **fields: Any) -> str:
    payload: dict[str, Any] = {
        "kind": kind,
    }
    payload.update(fields)
    return _json_resource(payload)


def _parse_addr_or_error(addr: str) -> tuple[Optional[int], Optional[str]]:
    from .utils import parse_address

    parsed = parse_address(addr)
    if not parsed["ok"] or parsed["value"] is None:
        return None, _resource_error("invalid_address", "Invalid address.", address=addr)
    return parsed["value"], None


def _function_summary(ea: int) -> Optional[dict[str, Any]]:
    if ida_funcs is None or idaapi is None:
        return None
    try:
        fn = ida_funcs.get_func(ea)
    except Exception:
        fn = None
    if not fn:
        return None
    return {
        "address": hex_addr(fn.start_ea),
        "name": idaapi.get_func_name(fn.start_ea),
        "end_address": hex_addr(fn.end_ea),
        "size": int(fn.end_ea) - int(fn.start_ea),
    }


def _list_functions_items() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if idautils is None:
        return items
    try:
        for ea in idautils.Functions():
            summary = _function_summary(int(ea))
            if summary:
                items.append(summary)
    except Exception:
        return items
    items.sort(key=lambda item: int(item["address"], 16))
    return items


def _list_strings_items() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for ea, length, stype, text in get_strings_cache():
        items.append(
            {
                "address": hex_addr(ea),
                "length": length,
                "type": stype,
                "text": text,
            }
        )
    return items


def _list_globals_items() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if idautils is None or ida_funcs is None:
        return items
    try:
        for ea, name in idautils.Names():
            try:
                fn = ida_funcs.get_func(ea)
                if fn and int(fn.start_ea) == int(ea):
                    continue
            except Exception:
                pass

            size = None
            try:
                size = ida_bytes.get_item_size(ea) if ida_bytes is not None else None
            except Exception:
                size = None
            items.append(
                {
                    "address": hex_addr(ea),
                    "name": name,
                    "size": size,
                }
            )
    except Exception:
        return items
    items.sort(key=lambda item: int(item["address"], 16))
    return items


def _list_types_items() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if ida_typeinf is None or idaapi is None:
        return items
    for ordinal in iter_local_type_ordinals(ida_typeinf):
        try:
            name = ida_typeinf.get_numbered_type_name(idaapi.cvar.idati, ordinal)  # type: ignore[attr-defined]
        except Exception:
            name = None
        if not name:
            continue

        decl = None
        try:
            tif = ida_typeinf.tinfo_t()
            ida_typeinf.get_numbered_type(idaapi.cvar.idati, ordinal, tif)  # type: ignore[attr-defined]
            try:
                decl = ida_typeinf.print_tinfo("", 0, 0, ida_typeinf.PRTYPE_1LINE, tif, name, "")  # type: ignore[attr-defined]
            except Exception:
                decl = None
        except Exception:
            decl = None

        if decl is None:
            decl = name
        items.append(
            {
                "ordinal": ordinal,
                "name": name,
                "decl": decl if len(decl) <= 256 else decl[:256] + "...",
            }
        )
    return items


def _normalize_segment_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": item.get("name"),
        "start_address": item.get("start_ea"),
        "end_address": item.get("end_ea"),
        "size": item.get("size"),
        "perm": item.get("perm"),
        "class": item.get("class"),
        "bitness": item.get("bitness"),
    }


def _list_import_items() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if idaapi is None:
        return items
    try:
        nimps = idaapi.get_import_module_qty()
        for index in range(nimps):
            module_name = idaapi.get_import_module_name(index)

            def _collect(ea: int, name: str, ordinal: int) -> bool:
                items.append(
                    {
                        "module": module_name,
                        "name": name,
                        "address": hex_addr(ea),
                        "ordinal": ordinal or None,
                    }
                )
                return True

            idaapi.enum_import_names(index, _collect)
    except Exception:
        return items
    items.sort(key=lambda item: (str(item.get("module") or ""), str(item.get("name") or "")))
    return items


def _list_export_items() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if idautils is None:
        return items
    try:
        for _, ordinal, ea, name in idautils.Entries():
            items.append(
                {
                    "name": name,
                    "address": hex_addr(ea),
                    "ordinal": ordinal or None,
                }
            )
    except Exception:
        return items
    items.sort(key=lambda item: int(item["address"], 16))
    return items


def _normalize_entry_point_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": item.get("name"),
        "address": hex_addr(item["ea"]),
        "ordinal": item.get("ordinal"),
    }


def _normalize_xref_item(item: dict[str, Any], direction: str) -> dict[str, Any]:
    if direction == "to":
        return {
            "address": item.get("frm"),
            "type": item.get("type"),
            "is_code": bool(item.get("iscode")),
        }
    return {
        "address": item.get("to"),
        "type": item.get("type"),
        "is_code": bool(item.get("iscode")),
    }


def _summarize_xrefs(address: str, items: list[dict[str, Any]], direction: str) -> str:
    grouped: dict[str, dict[str, Any]] = {}
    code_count = 0

    for item in items:
        ref_address = item.get("address")
        if not isinstance(ref_address, str):
            continue
        if item.get("is_code"):
            code_count += 1

        key = ref_address
        name = None
        fn_address = None
        try:
            ref_int = int(ref_address, 16)
            if ida_funcs is not None and idaapi is not None:
                fn = ida_funcs.get_func(ref_int)
                if fn:
                    fn_address = hex_addr(fn.start_ea)
                    name = idaapi.get_func_name(fn.start_ea)
                    key = fn_address
        except Exception:
            pass

        bucket = grouped.setdefault(
            key,
            {
                "address": fn_address or ref_address,
                "name": name,
                "count": 0,
            },
        )
        bucket["count"] += 1

    summary_items = sorted(grouped.values(), key=lambda item: (-item["count"], item["address"]))
    return _resource_detail(
        f"xrefs_{direction}_summary",
        address=address,
        count=len(items),
        code_count=code_count,
        data_count=len(items) - code_count,
        items=summary_items,
    )


def _segment_detail_from_name_or_addr(name_or_addr: str) -> Optional[dict[str, Any]]:
    from .api_core import list_segments

    segments = list_segments.__wrapped__().get("items", [])

    parsed_address = None
    try:
        parsed_address, _ = _parse_addr_or_error(name_or_addr)
    except Exception:
        parsed_address = None

    for item in segments:
        normalized = _normalize_segment_item(item)
        if normalized["name"] == name_or_addr:
            return normalized
        if parsed_address is not None:
            start = int(normalized["start_address"], 16)
            end = int(normalized["end_address"], 16)
            if start <= parsed_address < end:
                return normalized
    return None


@resource(uri="ida://idb/metadata")
@idaread
def idb_metadata_resource() -> str:
    from .api_core import get_metadata

    return _resource_detail("idb_metadata", **get_metadata.__wrapped__())


@resource(uri="ida://functions")
@idaread
def functions_resource() -> str:
    return _resource_list("functions", _list_functions_items())


@resource(uri="ida://function/{addr}")
@idaread
def function_resource(addr: str) -> str:
    address, error = _parse_addr_or_error(addr)
    if error:
        return error
    assert address is not None
    item = _function_summary(address)
    if not item:
        return _resource_error("function_not_found", "Function not found.", address=addr)
    return _resource_detail("function", **item)


@resource(uri="ida://function/{addr}/decompile")
@idaread
def function_decompile_resource(addr: str) -> str:
    from .api_analysis import decompile_function

    result = decompile_function(addr)
    if result.get("error"):
        error = str(result["error"])
        code = "function_not_found" if "not found" in error else "decompile_failed"
        return _resource_error(code, error, address=addr)
    return _resource_detail(
        "function_decompile",
        address=result.get("start_ea"),
        name=result.get("name"),
        end_address=result.get("end_ea"),
        decompiled=result.get("decompiled"),
    )


@resource(uri="ida://function/{addr}/disasm")
@idaread
def function_disasm_resource(addr: str) -> str:
    from .api_analysis import disassemble_function

    result = disassemble_function(addr)
    if result.get("error"):
        return _resource_error("disasm_failed", str(result["error"]), address=addr)
    instructions = [
        {
            "address": hex_addr(item["ea"]),
            "bytes": item.get("bytes"),
            "text": item.get("text"),
            "comment": item.get("comment"),
        }
        for item in result.get("instructions", [])
    ]
    return _resource_detail(
        "function_disasm",
        address=hex_addr(result["start_ea"]),
        name=result.get("name"),
        end_address=hex_addr(result["end_ea"]),
        count=len(instructions),
        items=instructions,
    )


@resource(uri="ida://function/{addr}/basic_blocks")
@idaread
def function_basic_blocks_resource(addr: str) -> str:
    from .api_analysis import basic_blocks_for_function

    result = basic_blocks_for_function(addr)
    if result.get("error"):
        return _resource_error("basic_blocks_failed", str(result["error"]), address=addr)
    blocks = [
        {
            "start_address": block.get("start_ea"),
            "end_address": block.get("end_ea"),
            "size": block.get("size"),
            "predecessors": block.get("predecessors", []),
            "successors": block.get("successors", []),
            "type": block.get("type"),
        }
        for block in result.get("blocks", [])
    ]
    return _resource_detail(
        "function_basic_blocks",
        address=result.get("start_ea"),
        name=result.get("function"),
        end_address=result.get("end_ea"),
        count=len(blocks),
        items=blocks,
    )


@resource(uri="ida://function/{addr}/stack")
@idaread
def function_stack_resource(addr: str) -> str:
    from .api_stack import stack_frame_for_function

    result = stack_frame_for_function(addr)
    if result.get("error"):
        return _resource_error("stack_frame_failed", str(result["error"]), address=addr)
    frame_variables = result.get("frame_variables", [])
    local_variables = result.get("local_variables", [])
    items = frame_variables or result.get("variables", [])
    return _resource_detail(
        "function_stack",
        address=result.get("start_ea"),
        name=result.get("name"),
        method=result.get("method"),
        count=len(items),
        items=items,
        frame_variables=frame_variables,
        local_variables=local_variables,
    )


@resource(uri="ida://strings")
@idaread
def strings_resource() -> str:
    return _resource_list("strings", _list_strings_items())


@resource(uri="ida://globals")
@idaread
def globals_resource() -> str:
    return _resource_list("globals", _list_globals_items())


@resource(uri="ida://types")
@idaread
def types_resource() -> str:
    return _resource_list("types", _list_types_items())


@resource(uri="ida://segments")
@idaread
def segments_resource() -> str:
    from .api_core import list_segments

    items = [_normalize_segment_item(item) for item in list_segments.__wrapped__().get("items", [])]
    return _resource_list("segments", items)


@resource(uri="ida://segment/{name_or_addr}")
@idaread
def segment_resource(name_or_addr: str) -> str:
    item = _segment_detail_from_name_or_addr(name_or_addr)
    if not item:
        return _resource_error("segment_not_found", "Segment not found.", query=name_or_addr)
    return _resource_detail("segment", **item)


@resource(uri="ida://imports")
@idaread
def imports_resource() -> str:
    return _resource_list("imports", _list_import_items())


@resource(uri="ida://imports/{module}")
@idaread
def imports_module_resource(module: str) -> str:
    items = [
        item
        for item in _list_import_items()
        if str(item.get("module", "")).lower() == module.lower()
    ]
    return _resource_detail("imports_module", module=module, count=len(items), items=items)


@resource(uri="ida://exports")
@idaread
def exports_resource() -> str:
    return _resource_list("exports", _list_export_items())


@resource(uri="ida://entry_points")
@idaread
def entry_points_resource() -> str:
    from .api_core import get_entry_points

    result = get_entry_points.__wrapped__()
    items = [_normalize_entry_point_item(item) for item in result.get("items", [])]
    return _resource_list("entry_points", items)


@resource(uri="ida://structs")
@idaread
def structs_resource() -> str:
    from .api_types import list_structs

    result = list_structs.__wrapped__()
    return _resource_list("structs", result.get("items", []))


@resource(uri="ida://struct/{name}")
@idaread
def struct_resource(name: str) -> str:
    from .api_types import get_struct_info

    result = get_struct_info.__wrapped__(name)
    if result.get("error"):
        return _resource_error("struct_not_found", str(result["error"]), name=name)
    return _resource_detail(
        "struct",
        name=result.get("name"),
        struct_kind=result.get("kind"),
        size=result.get("size"),
        count=result.get("member_count", 0),
        items=result.get("members", []),
    )


@resource(uri="ida://xrefs/to/{addr}")
@idaread
def xrefs_to_resource(addr: str) -> str:
    from .api_analysis import xrefs_to_address

    result = xrefs_to_address(addr)
    if result.get("error"):
        return _resource_error("xrefs_to_failed", str(result["error"]), address=addr)
    items = [_normalize_xref_item(item, "to") for item in result.get("xrefs", [])]
    return _resource_detail("xrefs_to", address=result.get("address"), count=len(items), items=items)


@resource(uri="ida://xrefs/to/{addr}/summary")
@idaread
def xrefs_to_summary_resource(addr: str) -> str:
    from .api_analysis import xrefs_to_address

    result = xrefs_to_address(addr)
    if result.get("error"):
        return _resource_error("xrefs_to_failed", str(result["error"]), address=addr)
    items = [_normalize_xref_item(item, "to") for item in result.get("xrefs", [])]
    return _summarize_xrefs(result.get("address", addr), items, "to")


@resource(uri="ida://xrefs/from/{addr}")
@idaread
def xrefs_from_resource(addr: str) -> str:
    from .api_analysis import xrefs_from_address

    result = xrefs_from_address(addr)
    if result.get("error"):
        return _resource_error("xrefs_from_failed", str(result["error"]), address=addr)
    items = [_normalize_xref_item(item, "from") for item in result.get("xrefs", [])]
    return _resource_detail("xrefs_from", address=result.get("address"), count=len(items), items=items)


@resource(uri="ida://xrefs/from/{addr}/summary")
@idaread
def xrefs_from_summary_resource(addr: str) -> str:
    from .api_analysis import xrefs_from_address

    result = xrefs_from_address(addr)
    if result.get("error"):
        return _resource_error("xrefs_from_failed", str(result["error"]), address=addr)
    items = [_normalize_xref_item(item, "from") for item in result.get("xrefs", [])]
    return _summarize_xrefs(result.get("address", addr), items, "from")


@resource(uri="ida://memory/{addr}")
@idaread
def memory_resource(addr: str, size: int = 16) -> str:
    from .api_memory import get_bytes

    address, error = _parse_addr_or_error(addr)
    if error:
        return error
    assert address is not None
    result = get_bytes.__wrapped__(hex_addr(address), size=size)
    if not result:
        return _resource_error("memory_read_failed", "Failed to read memory.", address=hex_addr(address))
    first = result[0]
    if first.get("error"):
        return _resource_error("memory_read_failed", str(first["error"]), address=hex_addr(address))
    return _resource_detail(
        "memory",
        address=hex_addr(address),
        size=first.get("size"),
        bytes=first.get("bytes"),
        hex=first.get("hex"),
    )


# SEMZ 解码速查手册（嵌为常量：插件安装后 instructor/ 目录不一定存在；
# 完整版见仓库 instructor/LLM_INSTRUCTOR.md）
_SEMZ_MANUAL = """\
SEMZ Ultra 速查手册（IDA-MCP compress_* 输出格式；完整版：instructor/LLM_INSTRUCTOR.md）

【定位】三者平等开放，按场景分流：
  正常代码理解语义 → decompile 最快（Hex-Rays 伪 C）。
  混淆/虚拟化代码（VMP、OLLVM 控制流扁平化等）、decompile 失败或输出可疑
    → 信任反汇编层：disasm 或 SEMZ。被混淆的基本块反编译出来看着像正常逻辑，
    伪 C 会产生误导性输出，信了就被骗。
  大范围扫读、批量传输 → SEMZ（compress_function / compress_range / compress_text）。
  看不懂 SEMZ 或需要原始汇编原文 → disasm_text（`0x<ea>: <text>` 纯文本逐行输出，
    同属可信反汇编层——混淆代码下警惕伪 C 误导的纪律不变）。
  IDA 未分析的数据区（壳层/JIT 缓冲）→ disasm_text/linear_disasm 自动回退 capstone
    字节级解码（响应带 fallback:"capstone"）；要变成真 IDB 代码先 force_code_range。
  不要逐行精读 ultra 输出；宏读不动用 expand_macros=true（全展开）或 "annotate"（引用行尾注释）。

【头部行】（# 开头，按需出现）
  #SZ1 fn=<名> arch=<arm64|x64|x86> at=0x<入口> o=<原指令数> u=<输出指令数> e=<死代码消除数> r=<字符比%>
  #summary blocks=<块数> macros=<#P 宏数> consts=<#K 常量数> jt=<间接跳转数>[(indirect)] frame=<帧大小>
  #K K0=<常量> …      常量池：重复≥2 的常量/符号，正文用 Kn 引用
  #P P0=<指令;指令;…> 序列宏：重复≥2 次的指令序列，正文整行 Pn 引用
  #J L7: L12,L9       跳转表：所在块 → 目标标签（unresolved = IDA 也未解析）
  #f=70               标准帧（序言/尾声）已消隐，帧大小 hex

【核心解码】（ARM64；x64/x86 见完整手册 §6）
  寄存器：a..z=x0..x25，A..E=x26..x30；S=sp，Z=xzr，P=pc；w 前缀=32 位视图（wa=w0）
  助记符：m=mov l=ldr s=str p=ldp q=stp c=bl r=ret j=b f=cmp t=tst d=adrp k=movk z=movz
  融合跳转：g<cc> Ln: f|t <ops> = cmp/tst + b.<cc>；独立条件跳写作 j<cc> Ln
  标签：Ln: 是基本块标签（L0=入口），不是地址；要地址映射加 with_map=true
  数制：hex 无 0x 前缀且以数字开头（0ff=0xff）；内存 [S+40]=[sp,#0x40]，预索引 [S-50]!，后索引 [S]+50
  e=n：n 条无副作用死代码已删，语义无损；不要编造被删指令内容
"""


@resource(uri="ida://semz/manual")
def semz_manual_resource() -> str:
    """SEMZ 解码速查（纯静态文本，不触 IDA，故不加 @idaread）。"""
    return _SEMZ_MANUAL


_SHELL_PLAYBOOK = """\
商业壳分析速查卡（IDA-MCP shell 工具层；完整版：instructor/SHELL_PLAYBOOK.md）

【决策树】
  1 triage_shell()        开局：格式/段/权限/字符串/syscall → 壳特征清单
  2 scan_regions()        DATA 段高熵区 = payload 候选（无需格式知识）
  3 find_algo_signatures()+scan_immediates()  三层指纹定位解压/解密函数
  4 emu_call(函数, args)  模拟执行 dump —— 禁止手写翻译（2 小时上限）
  5 write-watch 报告      写入区出现 ELF/PE/DEX 魔数 = 明文到手
  6 extract_layer(addr,size) → open_in_ida  新实例立刻并行下一层

【三层指纹】魔改算法扫不到标准字节签名，必须分层：
  L1 已知常量（AES/SM4/ChaCha/SHA/MD5/CRC32/Base64 表）——只抓标准件
  L2 256 字节全排列统计检测——自定义 S-box 也跑不掉
  L3 scan_immediates：range coder(0x1000000/0x800/1024/1846/768)、TEA delta、
     SHA/MD5 链值、CRC32 多项式 + 高 popcount 异常常量排行——魔改算法现形层

【铁律】
  - 模拟执行优先（emu_call/emu_run）；手写翻译 >2h 必须停手回到模拟路线
  - 追数据不追寄存器：entropy/magic/write-watch 胜过寄存器传播链
  - 混淆/虚拟化代码不信 decompile，信任 disasm/SEMZ 层
  - ABI：arm64=aapcs64 arm=aapcs32 x64-ELF=sysv64 x64-PE=win64 x86=cdecl
  - 模拟失败按升级阶梯：Unicorn→补环境→QEMU→调试器→静态裂缝→抠代码→手写
  - 落盘文件在 %TEMP%/ida_mcp_out/，任务结束征得确认后删除
  - JIT/翻译缓存块依赖活动 rbp/rsp 帧上下文，emu 跑不出真实行为 → 走静态
    （scan_blocks/disasm_text/force_code_range）或显式 regs

【未分析区与运行时内存】
  - disasm_text/linear_disasm 对 IDA 未分析区自动 capstone 兜底；要真 IDB 代码
    先 force_code_range(start,end)——别手工 undefine+make_code 逐段重试
  - 运行时内存：load_memory_dump(file,base) 载入 dump 为临时段；
    dump_process(pid,ranges) 直接抓活动进程；analyze_dump(file,base) 一条龙
    （载入→入口启发→强制解码→预览）。载入后常规工具全部可用
  - JIT/缓存：scan_blocks 块入口扫描；resolve_jump_slots 编码槽分类；
    find_refs_in_range 全缓存引用扫描=判定点发现；diff_regions 两 dump 对比
  - OLLVM：detect_ollvm 评分（≥60 likely_ollvm）；ollvm_simplify 保守简化
    （默认 dry_run，宁漏勿错）
"""


@resource(uri="ida://shell/playbook")
def shell_playbook_resource() -> str:
    """商业壳分析速查卡（纯静态文本，不触 IDA，故不加 @idaread）。"""
    return _SHELL_PLAYBOOK


_VERIFIER_PROMPT = """\
你是逆向分析结论的**对抗核查员**。你的唯一任务是证伪，不是确认。
另一位分析代理给出了一份脱壳裁决，请你独立核查并判定：CONFIRMED / REFUTED / UNCERTAIN。

【待核查声明】
- 样本/函数: {function}
- 声称的算法族: {algorithm}
- 声称的参数绑定: {args}
- 产物文件: {dump_file}
- 编排器裁决: {verdict_json}

【核查清单（逐条给证据）】
1. 产物存在且非空：sha256/大小与裁决书一致吗？
2. 魔数/结构：dump 头部的魔数与声称的明文类型一致吗？没有魔数时，声明的"代码"是否有
   合理指令密度（线性反汇编前 64 条，无效率 <10%）？
3. 尺寸闭环：produced == expected 吗？消耗 input == 提供的 in_size 吗？截断即 REFUTED 候选。
4. 熵剖面：输入 >7.5 且输出明显下降吗？输出仍 >7.5 → 很可能没解开（REFUTED）。
5. 边界正确性：dump 尾部是被截断的半条指令/半块结构吗？
6. 反证尝试：把产物当声称的格式再处理一次（如声称是 ARM64 代码就执行/反汇编；
   声称是 ELF 就解析程序头），任何一步失败都要如实写出。
7. 裁决书 review_flags 里的每条启发式假设：哪条错了会导致结论崩塌？验证最脆的那条。

【纪律】不得引用分析代理的推理作为证据；只接受你亲自复算的事实。
输出：判定 + 每条清单的证据 + 最可能推翻结论的下一步动作（若有）。
"""


@resource(uri="ida://shell/verifier_prompt")
def shell_verifier_prompt_resource() -> str:
    """对抗核查提示词模板（纯静态文本，不触 IDA，故不加 @idaread）。"""
    return _VERIFIER_PROMPT
