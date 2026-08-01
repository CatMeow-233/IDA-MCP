# IDA-MCP API Reference

本文档基于当前独立 IDA-MCP 插件仓库实现整理，覆盖：

- MCP 对外 HTTP 端点
- Gateway MCP proxy 工具
- 直连 IDA instance 工具
- `ida://` 资源
- Gateway 内部 HTTP 路由

仓库根目录包含 `ida_mcp.py`、`ida_mcp/`、`ida-plugin.json`、`requirements.txt`
和 live-IDA 测试套件 `test/`。Sarma IDE 通过 Git submodule 消费本仓库。

## 1. HTTP Endpoints

| Surface | URL | Purpose |
| --- | --- | --- |
| Gateway MCP proxy | `http://127.0.0.1:11338/mcp` | 多实例统一入口，只暴露 tools，不转发 `ida://` resources |
| Direct IDA instance MCP | `http://127.0.0.1:<instance_port>/mcp/` | 单实例直连入口，暴露 tools 和 `ida://` resources |
| Gateway internal HTTP | `http://127.0.0.1:11338/internal/*` | 非 MCP 内部控制/注册/转发接口 |

说明：

- `http_host` 控制 gateway 监听地址；所有 gateway 请求都必须携带匹配的 `gateway_token`，为空时网关拒绝请求
- Gateway MCP proxy 的默认 URL 由 `config.conf` 中的 `http_host/http_port/http_path` 决定
- Direct instance 端点固定为 `http://127.0.0.1:<instance_port>/mcp/`

## 2. MCP Call Conventions

### 2.1 Logical Request Shapes

工具调用逻辑上等价于：

```json
{
  "name": "list_functions",
  "arguments": {
    "offset": 0,
    "count": 10
  }
}
```

资源读取逻辑上等价于：

```json
{
  "uri": "ida://function/0x401000/decompile"
}
```

本文后续每个工具的“请求示例”都只写 `arguments` 内容；实际调用时请由 MCP client 包装为 `tools/call`。

### 2.2 Address Inputs

大多数地址参数支持：

- 十进制整数
- `0x401000`
- `401000h`
- `0x40_10_00`

部分工具支持逗号分隔批量输入，例如：

```json
{
  "addr": "0x401000,sub_402000,main"
}
```

### 2.3 Proxy Forwarded Tool Extras

除 proxy 自己实现的管理/生命周期工具外，所有“后端工具”在 Gateway MCP proxy 上调用时都额外支持：

- `port?: int`
- `timeout?: int`

示例：

```json
{
  "addr": "0x401000",
  "port": 10000,
  "timeout": 30
}
```

### 2.4 Common Response Shapes

分页工具统一返回：

```json
{
  "total": 123,
  "offset": 0,
  "count": 10,
  "items": []
}
```

实例工具常见错误格式：

```json
{
  "error": "invalid address"
}
```

gateway/control 面的包装错误常见格式：

```json
{
  "error": {
    "code": "instance_not_found",
    "message": "Port 10000 not found in registered instances.",
    "details": {
      "port": 10000
    }
  }
}
```

## 3. Gateway MCP Proxy Tools

这些工具只在 Gateway MCP proxy 暴露，直连实例没有对应工具名。

### 3.1 Management

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `check_connection` | none | `{}` | `{ok: bool, count: int}` |
| `list_instances` | none | `{}` | `[{pid, port, input_file, idb, started, python, ...}]` |
| `select_instance` | `port?: int` | `{"port": 10000}` | 设置后续未显式传 `port` 的默认实例，返回 `{selected_port}` 或包装错误 |

### 3.2 Lifecycle

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `open_in_ida` | `file_path: str`, `extra_args?: string[]` | `{"file_path":"D:\\samples\\a.exe"}` | 成功时 `{status, message, requested_port, launch_bundle, staged_file, launch_target}`；失败时 `{error}` |
| `close_ida` | `save?: bool`, `port?: int`, `timeout?: int` | `{"save":false,"port":10000}` | 直返目标实例 `close_ida` 结果，典型为 `{status:"ok", message:"IDA is closing"}` 或包装错误 |
| `shutdown_gateway` | `force?: bool`, `timeout?: int` | `{"force":true}` | `{status:"ok", message, forced, instance_count}` 或 `{error}` |

`open_in_ida` 当前行为：

- 启动 IDA 子进程时设置 `IDA_MCP_AUTO_START=1`
- 同时设置预留端口环境变量 `IDA_MCP_PORT`
- `open_in_ida` 会读取 `config.conf` 里的 `open_in_ida_autonomous` 来决定是否追加 `-A`
- 如果 `open_in_ida_bundle_dir` 已配置，则会在该目录下创建时间戳子目录
- 若目标旁边存在匹配的 `.i64/.idb`，则优先打开数据库，以避免再次弹出 loader/options 确认框
- `-A` 会把 IDA 切到 batch/autonomous 启动模式，更适合无人值守自动化；如果你需要正常交互式 GUI 流程，请把 `open_in_ida_autonomous=false`
- `wsl_path_bridge=false` 时，不做 Windows/WSL 路径转换
- `wsl_path_bridge=true` 时，`ida_path` 和 `open_in_ida_bundle_dir` 视为宿主机 Windows 路径；`open_in_ida` 会把可转换的 WSL 挂载路径转换成 Windows 路径后再启动 IDA
- `wsl_path_bridge=true` 且最终启动目标不能转换为 Windows 路径时，`open_in_ida` 会返回错误；此时应配置 `open_in_ida_bundle_dir`，先 staging 到 Windows 盘

## 4. Backend Tool Catalog

以下工具在 direct instance MCP 直接可用。

以下工具在 Gateway MCP proxy 上也可用，但会额外接受 `port?` 与 `timeout?`。

如果 `enable_unsafe=false`，则 `py_eval`、`patch_bytes`、`apply_patch` 与全部 `dbg_*` 工具不会注册。

### 4.1 Core Tools

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `check_connection` | none | `{}` | `{ok: bool, count: int}` |
| `list_instances` | none | `{}` | `[{pid, port, input_file, idb, started, ...}]` |
| `get_metadata` | none | `{}` | `{input_file, arch, bits, endian, hash}` |
| `list_functions` | `offset?: int`, `count?: int`, `pattern?: str` | `{"offset":0,"count":20,"pattern":"sub_*"}` | 分页结果；`items` 为 `[{name, start_ea, end_ea}]` |
| `list_globals` | `offset?: int`, `count?: int`, `pattern?: str` | `{"pattern":"g_*"}` | 分页结果；`items` 为 `[{name, ea, size}]` |
| `list_strings` | `offset?: int`, `count?: int`, `pattern?: str`, `regex?: bool` | `{"pattern":"^http","regex":true}` | 分页结果；默认对子串做大小写不敏感匹配；`regex=true` 时将 `pattern` 作为正则；`items` 为 `[{ea, length, type, text}]` |
| `list_local_types` | none | `{}` | `{total, items:[{ordinal, name, decl}]}` |
| `get_entry_points` | none | `{}` | `{total, items:[{ordinal, ea, name}]}` |
| `convert_number` | `text: str`, `size?: int` | `{"text":"401000h","size":64}` | `{input, size, value, hex, dec, unsigned, signed, bin, bytes_le, bytes_be}` |
| `list_imports` | `offset?: int`, `count?: int`, `pattern?: str` | `{"pattern":"kernel32"}` | 分页结果；`items` 为 `[{ea, name, ordinal, module}]` |
| `list_exports` | `offset?: int`, `count?: int`, `pattern?: str` | `{"count":50}` | 分页结果；`items` 为 `[{ea, name, ordinal}]` |
| `list_segments` | none | `{}` | `{total, items:[{name, start_ea, end_ea, size, perm, class, bitness}]}` |
| `get_cursor` | none | `{}` | `{ea, ea_int, function?, selection?}` |

### 4.2 Analysis Tools

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `decompile` | `addr: int | str` | `{"addr":"0x401000,main"}` | `[{query, name, start_ea, end_ea, decompiled, error}]` |
| `disasm` | `addr: int | str` | `{"addr":"0x401000"}` | `[{query, name, start_ea, end_ea, instructions, error}]`；`instructions` 为 `[{ea, bytes, text, comment}]` |
| `disasm_text` | `query?: int | str`（函数地址/名）或 `start`+`end`（范围），加分页/落盘参数 | `{"query":"main"}` 或 `{"start":"0xD90","end":"0x26DC"}` | 纯文本反汇编（无 SEMZ 编码）：`{name, ea, instructions, truncated, disasm}`，`disasm` 为 `0x<ea>: <text>` 逐行文本（有注释带 ` ; <comment>`）恒排最后；分页附加 `line_offset`/`line_total`，`out_file` 落盘返回 `{name, ea, instructions, file, chars}`。混淆/虚拟化代码（VMP/OLLVM）下的可信地面真相——伪 C 会失败或误导，信任反汇编层。范围模式下 IDA 未分析的数据区（无指令项）自动回退 capstone 字节级解码（响应含 `fallback:"capstone"`, `arch`），纯读不改 IDB；需要变成真正的 IDB 代码（可 decompile/xref）时先调 `force_code_range` |
| `linear_disasm` | `start_address: int | str`, `count?: int` | `{"start_address":"0x401000","count":16}` | `{start_address, count, instructions, truncated?}`；`instructions` 为 `[{ea, bytes, text, is_code, len}]`。IDA 无法解码时自动回退 capstone（响应含 `fallback:"capstone"`），仍失败返回 `{error:"decode_failed", hint}` |
| `get_callers` | `addr: int | str` | `{"addr":"main"}` | `{query, function, start_ea, end_ea, total, items}`；`items` 为 `[{address, name, call_count, call_sites}]` |
| `get_callees` | `addr: int | str` | `{"addr":"main"}` | `{query, function, start_ea, end_ea, total, items}`；`items` 为 `[{address, name, call_count, call_sites}]` |
| `get_function_signature` | `addr: int | str` | `{"addr":"0x401000"}` | `{query, function, start_ea, end_ea, signature, source, inferred}` |
| `xrefs_to` | `addr: int | str` | `{"addr":"0x401000,0x402000"}` | `[{query, address, total, xrefs, error}]`；`xrefs` 为 `[{frm, type, iscode}]` |
| `xrefs_from` | `addr: int | str` | `{"addr":"0x401000"}` | `[{query, address, total, xrefs, error}]`；`xrefs` 为 `[{to, type, iscode}]` |
| `xrefs_to_field` | `struct_name: str`, `field_name: str` | `{"struct_name":"MY_STRUCT","field_name":"vtable"}` | `{struct, field, offset, matches, truncated?, note?}`；`matches` 为 `[{ea, line}]` |
| `find_bytes` | `pattern: str`, `start?: str`, `end?: str`, `limit?: int` | `{"pattern":"48 8B ?? ?? 48 89","limit":20}` | `{pattern, ida_pattern, total, matches, truncated?}`；`matches` 为 `[{ea, bytes, function}]` |
| `get_basic_blocks` | `addr: int | str` | `{"addr":"main"}` | `{query, function, start_ea, end_ea, total, blocks}`；`blocks` 为 `[{start_ea, end_ea, size, predecessors, successors, type?}]` |

### 4.3 Memory Tools

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `get_bytes` | `addr: int | str`, `size?: int` (1..4096), `offset?: int` | `{"addr":"0x401000","size":16,"offset":32}` | `[{query, address, offset, size, bytes, hex}]` 或每项 `{error, query, address?}`；大区域按 `offset += 返回 size` 翻页 |
| `read_scalar` | `addr: int | str`, `width?: int`, `signed?: bool` | `{"addr":"0x401000","width":4,"signed":false}` | `[{query, address, width, signed, value, unsigned, hex}]` |
| `get_string` | `addr: int | str`, `max_len?: int` | `{"addr":"0x404000","max_len":128}` | `[{query, address, length, text}]` |

### 4.3.1 Compress Tools (SEMZ)

把反汇编压缩为 SEMZ DSL 文本（面向 LLM 的体积压缩）。场景分流：正常代码理解语义用 `decompile` 最快；混淆/虚拟化代码（VMP/OLLVM）或 decompile 失败/输出可疑时信任反汇编层（`disasm` 或 SEMZ——伪 C 可能误导）；大范围扫读/批量传输用 SEMZ；看不懂 SEMZ 或需要原始汇编原文用 `disasm_text`。解码手册见 MCP resource `ida://semz/manual` 或 `instructor/LLM_INSTRUCTOR.md`。三工具共用参数与返回约定：

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `compress_function` | `query: int | str`, `level?: safe\|full\|max\|ultra`, `arch?: auto\|x86\|x64\|arm64`, 加分页/落盘参数 | `{"query":"main","level":"ultra"}` | 见下方返回约定 |
| `compress_range` | `start: int | str`, `end: int | str`, `level?`, `arch?`, 加分页/落盘参数 | `{"start":"0xD90","end":"0x26DC"}` | 同上 |
| `compress_text` | `asm_text: str`, `level?`, `arch?`, 加分页/落盘参数 | `{"asm_text":"mov rax,1\n..."}` | 同上；纯计算，不触 IDA SDK |
| `extract_block` | `query: int | str`, `labels: str | str[]`（如 `"L7"` / `"L7,L8"` / `["L7","L8"]`）, `expand_macros?: bool \| "annotate"` | `{"query":"main","labels":"L7,L8,L9"}` | `{name, ea, labels, map, text}`：`text` = 头部行（`#SZ1/#summary/#K/#P/#J/#f`）+ 仅所求块的原文行；`map` 为所求标签→块首地址。标签不存在时返回 `{error, available}` |

分页/落盘参数（compress_* 三工具均有，优先级 `out_file` > 分页 > 默认全文）：

- `line_offset?: int`（默认 0）、`line_limit?: int`：按行切片，响应附加 `line_offset`/`line_total`；第 0 页含 `#SZ1/#K/#P` 头部
- `out_file?: str`：全文写盘（不受 120,000 字符截断限制），相对路径落到 `%TEMP%/ida_mcp_out/`，返回 `{name, ea, level, stats, file, chars}`，不回传 `compressed`
- `expand_macros?: bool | "annotate"`：`true` 内联展开全部 `#P` 序列宏（输出无宏定义/引用）；`"annotate"` 保留 `#P` 定义与引用行，在每个宏引用行尾追加 `; = <展开指令序列>` 注释
- `with_map?: bool`：附带 Ln 标签 → 块首地址映射。内联返回时加 `map` 字段（`{"L0":"0x..",...}`）；`out_file` 落盘时写 sidecar `<out_file>.map.json` 并返回 `map_file`。函数内直接跳转目标恒渲染为 Ln 标签（含 IDA 已命名 `loc_xxx` 目标），map 与压缩文本标签一一对应

`extract_block` 说明：重跑确定性 ultra 压缩（标签按地址序分配，与 `compress_function` 输出一致）后按标签切片，用于给块分析子代理准备分片 prompt，替代手工切分完整压缩文本。

返回约定：

- 默认：`{name, ea, level, stats, hint, truncated, compressed}`；`compressed` 恒排最后，显示截断时 `stats`（`{orig, out, elim, ratio}`）仍可读；超过 120,000 字符截断并置 `truncated=true`。`hint` 为场景分流提示（decompile/disasm/SEMZ 各自适用场景与解码手册位置），仅随响应返回，不落盘、不拼进 `compressed` 文本
- ultra 头部 `#SZ1` 行后恒有一行 `#summary blocks=N macros=M consts=K jt=J[(indirect)] [frame=F]`：块数/宏数/常量池大小/间接跳转数（`jt=0` 无 `(indirect)` 后缀）/帧大小（无帧消隐时省略 frame 字段），供解码前快速判断形态
- 压缩级别：`safe`（仅字典）、`full`（+保守死代码消除）、`max`（+nop/融合）、`ultra`（默认，全局固定表 + 帧消隐 `#f=N` + 宏 `#P` + 常量池 `#K`）
- `arch=auto`：IDA 侧工具按 IDB `procname`+位宽判定，`compress_text` 按寄存器/助记符启发式判定
- 压缩格式（`#SZ1` 头部、`#summary` 摘要行、`#K` 常量池、`#P` 序列宏、融合行）的完整解码规则见 `instructor/LLM_INSTRUCTOR.md`；速查版见 MCP resource `ida://semz/manual`

### 4.3.2 Shell/Packer Tools（商业壳分析）

面向商业壳/加固样本的工具层（架构与格式通用：arm64/arm/x86/x64，ELF/PE/Mach-O）。方法论见 MCP resource `ida://shell/playbook` 与 `instructor/SHELL_PLAYBOOK.md`。核心原则：**模拟执行优先，禁止手写翻译器（2 小时上限）；追数据不追寄存器**。

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `triage_shell` | `max_insns?: int` | `{}` | `{format, header, arch, bits, segments, imports, exports, string_hits, syscall_scan, traits, next}`；`header.no_section_headers`/`segments.rwx`/`traits[]` 为壳特征证据 |
| `scan_regions` | `min_region?: int`, `include_exec?: bool` | `{}` | `{bytes_scanned, high_entropy_regions, magics, hint}`；高熵区 = payload 候选（格式无关） |
| `find_embedded_files` | none | `{}` | `{count, files:[{type, offset, address, confidence, note, segment}], hint}` |
| `find_algo_signatures` | `with_xrefs?: bool`, `perms?: bool` | `{}` | `{constants, permutation_tables, layers_note, hint}`；三层指纹的 L1（已知常量表）+L2（256 字节全排列=自定义 S-box），每项附 `referenced_by` 候选函数 |
| `scan_immediates` | `top?: int`, `max_insns?: int` | `{"top":25}` | `{insns_scanned, partial, functions:[{function, ea, score, watch_hits, suspicious_constants}], hint}`；L3 指纹：range-coder/TEA/ChaCha/SHA/CRC32/SM4 常量 watchlist + 高 popcount 异常常量排行，**魔改算法在此层现形** |
| `dump_region` | `addr: int \| str`, `size?: int`, `name?: str` | `{"addr":"0x700000","size":65536}` | `{file, address, size, sha256, head_hex, magics}`；文件落盘 `%TEMP%/ida_mcp_out/` |
| `extract_layer` | `addr: int \| str`, `size: int`, `name?: str` | `{"addr":"0x700000","size":65536,"name":"layer2.so"}` | dump_region 字段 + `next_step`（调 `open_in_ida` 开新实例并行下一层） |
| `emu_run` | `start: int \| str`, `stop_at?`, `regs?`, `writes?`, `arch?: auto\|arm64\|arm\|x64\|x86`, `max_instructions?`, `watch_writes?: bool`, `dump?: bool` | `{"start":"0x5774CC","stop_at":"0x577900","watch_writes":true}` | `{ok, stop_reason, pc, instructions, regs, svc_log, dirty, readback_summary, fault?}`；write-watch 对写入区做魔数/熵扫描——明文落点算法无关可见 |
| `emu_call` | `func: int \| str`, `args?: [...]`（`"@in"`/`"@out"` 指代模拟缓冲区）, `abi?: auto\|aapcs64\|aapcs32\|sysv64\|win64\|cdecl`, `in_addr?`, `in_size?`, `out_size?`, `out_name?`, `regs?`, `max_instructions?` | `{"func":"sub_5774CC","args":["@in","@out",0],"in_addr":"0x90000","in_size":32768,"out_size":262144}` | emu_run 字段 + `{abi, buffers, readback_summary}`；`stop_reason="sentinel"` 为正常返回；输出缓冲区自动落盘并扫魔数 |

`emu_*` 依赖 IDA Python 环境安装 `unicorn`（已列入 requirements.txt；未安装时工具返回明确错误）。ABI 预设：arm64=aapcs64(x0-x7)、arm=aapcs32(r0-r3)、x64-ELF=sysv64(rdi,rsi,rdx,rcx,r8,r9)、x64-PE=win64(rcx,rdx,r8,r9)、x86=cdecl（栈参）。**适用边界**：模拟执行从干净 CPU 上下文起步，依赖活动进程帧上下文（rbp/rsp 帧、宿主预置寄存器）的 JIT/翻译缓存块在 `emu_run`/`emu_call` 下不会得到真实行为——此类块请走静态路径（`scan_blocks`/`disasm_text`/`force_code_range`）或显式传 `regs`。

### 4.3.3 Runtime Dump Tools（运行时内存载入）

壳分析 80% 是运行时内存：把内存 dump 载入 IDB 后，全部常规工具（decompile/disasm/xrefs/emu_*）即可直接使用。

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `load_memory_dump` | `file: str`, `base: int \| str`, `size?: int`（0=全文件）, `name?: str`, `perm?: str`, `bitness?: int`, `seg_class?: str` | `{"file":"layer2.bin","base":"0x700000"}` | 段信息 `{name, start_ea, end_ea, size, ...}` + `hint`；文件 ≤64MB，base 被占用返回 `{error}` |
| `dump_process` | `pid: int`, `ranges: str \| list`（`"0x7f0000-0x7f2000,0x800000+0x1000"`）, `perm?: str` | `{"pid":1234,"ranges":"0x400000-0x410000"}` | `{loaded: [...], failed_ranges: [...]}`；Windows 走 ReadProcessMemory，Linux 读 /proc/pid/mem；unsafe 工具。单段 ≤64MB、总量 ≤256MB |
| `analyze_dump` | `file: str`, `base: int \| str`, `entry?: int \| str`, `bitness?: int` | `{"file":"dump.bin","base":"0x700000"}` | 工作流编排（一次调用替代多轮）：load dump → 入口启发式（MZ/ELF magic，否则 x86 序言扫描）→ `force_code_range` 强制解码 → capstone 预览，返回 `{segment, entry, entry_candidates, forced, disasm_preview, hints}` |

### 4.3.4 JIT/Translation-Cache Tools（翻译缓存/JIT 分析）

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `scan_blocks` | `base: int \| str`, `end: int \| str`, `pattern?: str`, `max_results?: int` | `{"base":"0x700000","end":"0x800000"}` | 块入口扫描：pattern 给定时字节模式搜索（`??` 通配）；缺省时 x86 序言签名 + 对齐启发，每条带 `signature` 名。范围 ≤16MB |
| `resolve_jump_slots` | `base`, `end`, `ptr_size?: int`, `max_results?: int` | `{"base":"0x700000","end":"0x710000"}` | 编码跳转槽懒解析检测（启发式）：槽位分类 `resolved`（指向可执行段）/`internal`（指向缓存内）/`suspicious`（未映射/数据段=疑似待解析编码槽） |
| `find_refs_in_range` | `base`, `end`, `target_start`, `target_end`, `ptr_size?: int`, `max_results?: int` | `{"base":"0x700000","end":"0x800000","target_start":"0x401000","target_end":"0x402000"}` | 全缓存引用扫描（判定点发现）：`[{slot, value, offset_into_target}]`，范围 ≤64MB |
| `diff_regions` | `source_a: str`, `source_b: str`, `size?: int`, `max_runs?: int` | `{"source_a":"old.bin","source_b":"0x700000","size":65536}` | 两 dump/两段内存对比（cmp 的 MCP 版）：`{identical, total_diff_bytes, diff_runs: [{offset, length, a_hex, b_hex}]}`；源可以是文件路径或 IDB 地址 |

### 4.3.5 OLLVM Tools（混淆检测/简化）

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `detect_ollvm` | `query: int \| str` | `{"query":"main"}` | `{score(0-100), verdict: likely_ollvm\|suspicious\|normal, metrics, evidence}`；指标：cmov 密度、不透明谓词命中、控制流平坦化信号（高扇入 dispatcher/块多 call 少/state 变量分发） |
| `ollvm_simplify` | `ea: int \| str`, `max_patches?: int`, `dry_run?: bool`（默认 true） | `{"ea":"0x401000","dry_run":false}` | 保守简化可静态判定的不透明谓词（`xor/sub/cmp reg,reg`+jcc 紧邻模式）：必跳→patch 短跳为 jmp，必不跳→NOP；`{patched: [{ea, kind, old_bytes, new_bytes}], skipped, dry_run}`。宁漏勿错，长跳(0F 8x)跳过并记录 |

### 4.4 Modeling Tools

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `create_function` | `address: int | str`, `end?: int | str` | `{"address":"0x401000"}` | `{address, requested_end, function, changed, note?}` 或 `{error}` |
| `delete_function` | `address: int | str` | `{"address":"0x401000"}` | `{address, old_function?, changed, note?}` |
| `make_code` | `address: int | str` | `{"address":"0x401020"}` | `{address, old_item, new_item, changed, note?}` 或 `{error}` |
| `undefine_items` | `address: int | str`, `size: int` | `{"address":"0x401020","size":16}` | `{address, size, old_item, new_item?, changed, note?}` 或 `{error}` |
| `make_data` | `address: int | str`, `data_type: str`, `count?: int` | `{"address":"0x404000","data_type":"dword","count":4}` | `{address, data_type, normalized_type, count, item_size, old_item, new_item, changed}` 或 `{error}` |
| `make_string` | `address: int | str`, `string_type?: str`, `length?: int` | `{"address":"0x404000","string_type":"c","length":32}` | `{address, string_type, length, old_item, new_item, changed}` 或 `{error}` |
| `force_code_range` | `start: int | str`, `end: int | str` | `{"start":"0x700000","end":"0x704000"}` | `{start_ea, end_ea, instructions_created, bytes_skipped, first_undecodable?}` 或 `{error}`。一次调用替代手工 undefine+make_code 多次重试：线性扫描强制解码 IDA 未分析的壳层/VM/JIT 缓冲区（上限 1 MiB），之后 disasm_text/decompile/compress_range 均可用 |

`old_item/new_item` 通常包含：

```json
{
  "ea": "0x404000",
  "head": "0x404000",
  "size": 4,
  "kind": "data",
  "function": {
    "name": "sub_401000",
    "start_ea": "0x401000",
    "end_ea": "0x401050"
  }
}
```

### 4.5 Modify Tools

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `set_comment` | `items: [{address, comment}]` | `{"items":[{"address":"0x401000","comment":"entry"}]}` | `[{address, old, new, changed, error}]` |
| `rename_function` | `address: int | str`, `new_name: str` | `{"address":"0x401000","new_name":"handle_init"}` | `{start_ea, old_name, new_name, changed, note?}` 或 `{error}` |
| `rename_local_variable` | `function_address: int | str`, `old_name: str`, `new_name: str` | `{"function_address":"0x401000","old_name":"v1","new_name":"ctx"}` | `{function, start_ea, old_name, new_name, changed}` 或 `{error}` |
| `rename_global_variable` | `old_name: str`, `new_name: str` | `{"old_name":"dword_404000","new_name":"g_state"}` | `{ea, old_name, new_name, changed, note?}` 或 `{error}` |
| `patch_bytes` | `items: [{address, bytes}]` | `{"items":[{"address":"0x401000","bytes":"90 90 90"}]}` | `[{address, size, patched, old_bytes, new_bytes, error}]` |
| `apply_patch` | `output_path?: str`, `overwrite?: bool` | `{"output_path":"a.patched.exe","overwrite":false}` | `{input_file, output_file, input_size, applied, skipped, patches, skipped_patches, truncated}` 或 `{error}` |

### 4.6 Stack Tools

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `stack_frame` | `addr: int | str` | `{"addr":"main"}` | `[{query, name, start_ea, method?, variables, frame_variables?, local_variables?, error?, note?}]` |
| `declare_stack` | `items: [{function_address, offset, name, type?, size?}]` | `{"items":[{"function_address":"0x401000","offset":-0x20,"name":"buf","type":"char[32]","size":32}]}` | `[{function_address, offset, name, declared_type?, size?, changed, error?, note?}]` |
| `delete_stack` | `items: [{function_address, name}]` | `{"items":[{"function_address":"0x401000","name":"buf"}]}` | `[{function_address, name, changed, deleted, error}]` |

### 4.7 Type Tools

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `declare_struct` | `decl: str` | `{"decl":"struct MY_S { int a; char b; };"}` | `{name, kind:"struct", created, replaced, success}` 或 `{error}` |
| `declare_enum` | `decl: str` | `{"decl":"enum MY_E { A=0, B=1 };"}` | `{name, kind:"enum", created, replaced, success}` 或 `{error}` |
| `declare_typedef` | `decl: str` | `{"decl":"typedef unsigned int MY_U32;"}` | `{name, kind:"typedef", created, replaced, success}` 或 `{error}` |
| `set_function_prototype` | `function_address: int | str`, `prototype: str` | `{"function_address":"0x401000","prototype":"int __fastcall sub_401000(int a1);"}` | `{start_ea, applied, old_type, new_type, parsed_name}` 或 `{error}` |
| `set_local_variable_type` | `function_address: int | str`, `variable_name: str`, `new_type: str` | `{"function_address":"0x401000","variable_name":"ctx","new_type":"MY_CTX *"}` | `{function, start_ea, variable_name, old_type, new_type, applied}` 或 `{error}` |
| `set_global_variable_type` | `variable_name: str`, `new_type: str` | `{"variable_name":"g_state","new_type":"int"}` | `{ea, variable_name, old_type, new_type, applied}` 或 `{error}` |
| `list_structs` | `pattern?: str` | `{"pattern":"web*"}` | `{total, items:[{ordinal, name, kind, size, members}]}` |
| `get_struct_info` | `name: str` | `{"name":"MY_S"}` | `{name, kind, size, members, member_count}` 或 `{error}` |

### 4.8 Python Tool

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `py_eval` | `code: str` | `{"code":"print(hex(ida_kernwin.get_screen_ea()))"}` | `{result, stdout, stderr}` |

说明：

- `py_eval` 被标记为 unsafe
- `result` 为字符串化结果
- 运行异常时 `stderr` 中包含 traceback
- 代码在单一模块式命名空间执行：函数闭包可读顶层变量、`import ... as` 别名正常绑定（与 exec 分离 globals/locals 的旧行为不同）

### 4.9 Debug Tools

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `dbg_regs` | none | `{}` | `{ok, registers, notes?, note?}`；`registers` 为 `[{name, value, int?}]` |
| `dbg_callstack` | none | `{}` | `{ok, frames, note?}`；`frames` 为 `[{index, ea, func}]` |
| `dbg_list_bps` | none | `{}` | `{ok, total, breakpoints}`；`breakpoints` 为 `[{ea, enabled?, size?, type?}]` |
| `dbg_start` | none | `{}` | `{ok, started, pid, suspended}` 或 `{error}` |
| `dbg_exit` | none | `{}` | `{ok, exited, note?}` 或 `{error}` |
| `dbg_continue` | none | `{}` | `{ok, continued, note?}` 或 `{error}` |
| `dbg_run_to` | `addr: int | str` | `{"addr":"0x401000"}` | `{ok, requested, continued, suspended?, used_temp_bpt, cleaned_temp_bpt, note?}` 或 `{error}` |
| `dbg_add_bp` | `addr: int | str` | `{"addr":"0x401000,0x401020"}` | `[{query, ok, ea, existed, added, error, note?}]` |
| `dbg_delete_bp` | `addr: int | str` | `{"addr":"0x401000"}` | `[{query, ok, ea, existed, deleted, error, note?}]` |
| `dbg_enable_bp` | `items: [{address, enable}]` | `{"items":[{"address":"0x401000","enable":false}]}` | `[{ok, ea, existed, enabled, changed, note?}]` 或每项 `{error}` |
| `dbg_step_into` | none | `{}` | `{ok, stepped, note?}` 或 `{error}` |
| `dbg_step_over` | none | `{}` | `{ok, stepped, note?}` 或 `{error}` |
| `dbg_read_mem` | `regions: [{address, size}]` | `{"regions":[{"address":"0x7FF600001000","size":32}]}` | `[{address, size, bytes, hex, error}]` |
| `dbg_write_mem` | `regions: [{address, bytes}]` | `{"regions":[{"address":"0x7FF600001000","bytes":[144,144]}]}` | `[{address, size, written, error}]` |

说明：

- 全部 debug 工具都被标记为 unsafe
- 大多数 debug 工具要求调试器已激活；未激活时通常返回 `{ok:false,...}` 或 `{error:"debugger not active"}`

### 4.10 Instance Lifecycle Tool

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `close_ida` | `save?: bool` | `{"save":true}` | `{status:"ok", message:"IDA is closing"}` 或 `{error}` |

## 5. Resource Catalog

资源只在 direct instance MCP 暴露，不通过 Gateway MCP proxy 转发。

逻辑读取方式为 `resources/read uri="..."`。

### 5.1 Common Resource Payloads

列表资源统一近似为：

```json
{
  "kind": "functions",
  "count": 2,
  "items": []
}
```

详情资源统一近似为：

```json
{
  "kind": "function",
  "address": "0x401000",
  "name": "main"
}
```

资源错误统一为：

```json
{
  "error": {
    "code": "function_not_found",
    "message": "Function not found.",
    "details": {
      "address": "0x401000"
    }
  }
}
```

### 5.2 Resource List

| URI | Parameters | Read Example | Expected Payload |
| --- | --- | --- | --- |
| `ida://idb/metadata` | none | `{"uri":"ida://idb/metadata"}` | `{kind:"idb_metadata", input_file, arch, bits, endian, hash}` |
| `ida://functions` | none | `{"uri":"ida://functions"}` | `{kind:"functions", count, items:[{address, name, end_address, size}]}` |
| `ida://function/{addr}` | `addr` path param | `{"uri":"ida://function/0x401000"}` | `{kind:"function", address, name, end_address, size}` |
| `ida://function/{addr}/decompile` | `addr` path param | `{"uri":"ida://function/0x401000/decompile"}` | `{kind:"function_decompile", address, name, end_address, decompiled}` |
| `ida://function/{addr}/disasm` | `addr` path param | `{"uri":"ida://function/0x401000/disasm"}` | `{kind:"function_disasm", address, name, end_address, count, items}`；`items` 为 `[{address, bytes, text, comment}]` |
| `ida://function/{addr}/basic_blocks` | `addr` path param | `{"uri":"ida://function/0x401000/basic_blocks"}` | `{kind:"function_basic_blocks", address, name, end_address, count, items}` |
| `ida://function/{addr}/stack` | `addr` path param | `{"uri":"ida://function/0x401000/stack"}` | `{kind:"function_stack", address, name, method, count, items, frame_variables?, local_variables?}` |
| `ida://strings` | none | `{"uri":"ida://strings"}` | `{kind:"strings", count, items:[{address, length, type, text}]}` |
| `ida://globals` | none | `{"uri":"ida://globals"}` | `{kind:"globals", count, items:[{address, name, size}]}` |
| `ida://types` | none | `{"uri":"ida://types"}` | `{kind:"types", count, items:[{ordinal, name, decl}]}` |
| `ida://segments` | none | `{"uri":"ida://segments"}` | `{kind:"segments", count, items:[{name, start_address, end_address, size, perm, class, bitness}]}` |
| `ida://segment/{name_or_addr}` | segment name or address | `{"uri":"ida://segment/.text"}` | `{kind:"segment", name, start_address, end_address, size, perm, class, bitness}` |
| `ida://imports` | none | `{"uri":"ida://imports"}` | `{kind:"imports", count, items:[{module, name, address, ordinal}]}` |
| `ida://imports/{module}` | module name | `{"uri":"ida://imports/kernel32"}` | `{kind:"imports_module", module, count, items}` |
| `ida://exports` | none | `{"uri":"ida://exports"}` | `{kind:"exports", count, items:[{name, address, ordinal}]}` |
| `ida://entry_points` | none | `{"uri":"ida://entry_points"}` | `{kind:"entry_points", count, items:[{name, address, ordinal}]}` |
| `ida://structs` | none | `{"uri":"ida://structs"}` | `{kind:"structs", count, items:[{ordinal, name, kind, size, members}]}` |
| `ida://struct/{name}` | struct name | `{"uri":"ida://struct/MY_S"}` | `{kind:"struct", name, struct_kind, size, count, items}` |
| `ida://xrefs/to/{addr}` | address | `{"uri":"ida://xrefs/to/0x401000"}` | `{kind:"xrefs_to", address, count, items:[{address, type, is_code}]}` |
| `ida://xrefs/to/{addr}/summary` | address | `{"uri":"ida://xrefs/to/0x401000/summary"}` | `{kind:"xrefs_to_summary", address, count, code_count, data_count, items}` |
| `ida://xrefs/from/{addr}` | address | `{"uri":"ida://xrefs/from/0x401000"}` | `{kind:"xrefs_from", address, count, items:[{address, type, is_code}]}` |
| `ida://xrefs/from/{addr}/summary` | address | `{"uri":"ida://xrefs/from/0x401000/summary"}` | `{kind:"xrefs_from_summary", address, count, code_count, data_count, items}` |
| `ida://memory/{addr}` | address path param, `size` query param | `{"uri":"ida://memory/0x401000?size=32"}` | `{kind:"memory", address, size, bytes, hex}` |
| `ida://shell/playbook` | none | `{"uri":"ida://shell/playbook"}` | 商业壳分析速查卡（纯静态文本；完整版 `instructor/SHELL_PLAYBOOK.md`） |

## 6. Gateway Internal HTTP Endpoints

这些路由不是 MCP 协议的一部分，但它们是当前网关实现实际暴露的 HTTP API。

Base URL:

```text
http://127.0.0.1:11338/internal
```

`http_host` 控制 gateway 监听地址。请求必须携带共享 token；`gateway_token` 为空时网关拒绝请求：

```http
Authorization: Bearer <gateway_token>
```

也支持 `X-IDA-MCP-Token: <gateway_token>`。是否允许非本机访问由 `http_host`、系统防火墙和网络环境决定；非本机访问应使用随机高强度 token，并保持 `enable_unsafe=false`，除非确实需要高危工具。

| Method | Path | Request Body | Expected Response |
| --- | --- | --- | --- |
| `GET` | `/healthz` | none | `{ok, gateway, gateway_proxy, instance_count, started_at}` |
| `GET` | `/instances` | none | 当前注册实例数组 |
| `GET` | `/current_instance` | none | `{port}` |
| `GET` | `/debug` | none | `{enabled}` |
| `POST` | `/debug` | `{"enable": true}` 或 `{"enabled": true}` | `{status:"ok", enabled}` |
| `GET` | `/gateway_proxy_status` | none | `{enabled, running, url, host, bind_host, port, path, last_error}` |
| `POST` | `/ensure_gateway_proxy` | none | 与 `/gateway_proxy_status` 相同 |
| `POST` | `/shutdown` | `{"force": false}` | 成功 `{status:"ok", message, forced, instance_count}`；存在实例且未 `force` 时 HTTP 409 |
| `POST` | `/register` | `{"pid":..., "port":..., ...}` | `{status:"ok"}`；缺字段时 HTTP 400 |
| `POST` | `/deregister` | `{"pid":...}` | `{status:"ok"}`；缺字段时 HTTP 400 |
| `POST` | `/select_instance` | `{"port":10000}` 或 `{}` | `{status:"ok", selected_port}`；找不到实例时 HTTP 404 |
| `POST` | `/call` | `{"tool":"list_functions","params":{},"port":10000,"timeout":30}` | 成功 `{tool, data}`；失败时 `{error}` |

### 6.1 `/call` Forwarding Rules

`POST /internal/call` 请求体字段：

- `tool: string`
- `params?: object`
- `pid?: int`
- `port?: int`
- `timeout?: int`

成功示例：

```json
{
  "tool": "get_metadata",
  "data": {
    "input_file": "D:\\samples\\a.exe",
    "arch": "x86_64",
    "bits": 64,
    "endian": "little",
    "hash": "..."
  }
}
```

失败示例：

```json
{
  "error": {
    "code": "instance_not_found",
    "message": "instance not found"
  }
}
```

## 7. Discovery Notes

标准 MCP discovery 仍然可用：

- `tools/list`
- `resources/list`
- `resources/read`

当前实现上的实际区别是：

- Gateway MCP proxy：主要用于多实例 tools
- Direct instance MCP：用于 tools + `ida://` resources
- 内部 HTTP：只给 gateway/proxy/runtime 使用，不建议普通 MCP client 直接依赖
