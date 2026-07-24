KIMI K3最新力作
# IDA-MCP

IDA-MCP is an IDA Pro plugin that exposes IDA analysis, database modification,
debugger, and lifecycle operations through MCP. Each IDA instance runs a local
FastMCP HTTP server, and a standalone gateway provides a stable
multi-instance MCP endpoint.

## Layout

```text
IDA-MCP/
├── ida_mcp.py          # IDA plugin entry point, exposes PLUGIN_ENTRY()
├── ida-plugin.json     # IDA plugin metadata
├── ida_mcp/            # plugin package, gateway, proxy, tools, resources
├── instructor/         # LLM instructor: SEMZ decoding manual + system prompt
├── install.py          # interactive installer
├── test/               # live-IDA pytest suite
├── API.md              # MCP, tool, resource, and internal HTTP contract
├── project.md          # repository map and boundaries
├── roadmap.md          # current direction and milestones
└── requirements.txt    # IDA Python runtime dependencies
```

## Runtime Model

- IDA loads `ida_mcp.py`, which starts `ida_mcp/plugin_runtime.py`.
- Each IDA instance chooses a free port starting at `ida_default_port` and serves MCP at `/mcp/`.
- The standalone gateway listens on `127.0.0.1:11338`, registers instances under `/internal/*`, and exposes the proxy MCP endpoint at `/mcp`.
- Tool registration is decorator based: use `@tool` plus `@idaread` or `@idawrite`.
- Gateway requests require `gateway_token`; an empty token fails closed.
- `py_eval`, `patch_bytes`, `apply_patch`, and `dbg_*` tools are unsafe and gated by `enable_unsafe=false` by default in `ida_mcp/config.conf`.

## SEMZ Compression Tools

SEMZ v1 (`ida_mcp/compress/`, pure Python, no IDA SDK dependency) compresses
disassembly into a compact self-contained DSL for LLM consumption: mnemonic /
register dictionaries (`#MN`/`#RG`), a constant pool (`#CT`), mined instruction
sequence macros (`#SQ`), basic-block labels, and conservative dead-code
elimination (`#ELIM`).

- `compress_function(query, level)` — resolve a function by address or name and
  compress it.
- `compress_range(start, end, level)` — linear-disassemble an address range
  (`idautils.Heads`) and compress it.
- `compress_text(asm_text, level)` — compress raw assembly / trace text
  (IDA export, x64dbg `addr | bytes | disasm` traces, or bare instructions);
  pure computation, does not touch the IDA SDK.
- `extract_block(query, labels)` — re-run the deterministic ultra compression
  and return the header lines plus only the requested blocks (`"L7"` /
  `"L7,L8"` / list), for feeding single blocks to sub-agents without
  hand-cutting the full text.

In-function direct branch targets are always rendered as `Ln` labels
(including IDA-named `loc_xxx` targets). Pass `with_map=true` to any
`compress_*` tool to get the label→address map (`{"L0":"0x..",...}` inline,
or an `<out_file>.map.json` sidecar when spilling to disk).

**LLM instructor**: `instructor/LLM_INSTRUCTOR.md` is the SEMZ decoding manual
(ARM64/x86/x64 fixed tables, ultra syntax, work rules) plus a ready-to-use
system-prompt template — attach it (or its 10-line quick card) whenever you
feed compressed text to a model; the fixed dictionaries deliberately never
travel with the output, which is where the compression ratio comes from.

`level` selects the aggressiveness: `safe` (dictionaries only, no elimination),
`full` (adds conservative liveness-based dead-code elimination with a deletion
log), `max` (adds nop/padding removal and cmp/test+jcc fusion, e.g.
`cjz L4: t a, a`), and `ultra` (the default: globally fixed mnemonic/register
tables with no `#MN`/`#RG` headers, always-on fusion `gz L5: t a` and DCE,
zeroing/test idioms, multi-push folding, standard stack-frame elision `#f=N`,
and constants/macros pooled only when repeated at least twice). All levels return `{name, ea, level, stats, truncated, compressed}`
(`compressed` last, so display truncation never hides the stats); inline output
longer than 120,000 characters is truncated. Large outputs can instead be paged
with `line_offset`/`line_limit` (line-granularity slices, response adds
`line_offset`/`line_total`) or spilled to disk with `out_file` (relative paths
land in `%TEMP%/ida_mcp_out/`; response returns `{..., file, chars}` without
`compressed`). Spilled files are temporary — delete them after the user
confirms the task is done.

ARM64 / x86 / x64 are all first-class targets (three architectures): all three
tools take an optional `arch` argument (`auto`/`x86`/`x64`/`arm64`, default
`auto` — heuristics on register names/`#imm`/mnemonics/`dword`/`qword` for
text, IDB `procname`+bitness for IDA-side tools). ARM64 gets its own fixed
ultra table (`q D,E,[S-50]!` = stp x29,x30, `geq L2: f a,10` = cmp+b.eq
fusion, `stp`/`ldp` frame elision `#f=N`); x86 (32-bit) reuses the x64
mnemonic table with bare register codes meaning 32-bit (`a`=eax), dword as the
default memory width, segment-prefix memory kept as `[fs+30]`, `retn N` kept
as `r N`, and `push ebp`-style frame elision `#f=N`.

## Installation

Requirements:

- Python > 3.11

Run the interactive installer from the repository root:

```bash
python install.py
```

The installer performs the full setup flow:

1. Locate the IDA installation directory.
2. Locate the IDAPython interpreter used by that IDA installation.
3. Optionally install `requirements.txt` into IDA's Python environment.
4. Copy `ida_mcp.py`, `ida-plugin.json`, and the `ida_mcp/` package into IDA's `plugins/` directory.
5. Review and write `ida_mcp/config.conf`, including an auto-generated gateway token.

For manual installation, copy `ida_mcp.py`, `ida-plugin.json`, and the
`ida_mcp/` directory into IDA's plugin directory, then install dependencies into
IDA's Python environment:

```bash
<ida_python> -m pip install -r requirements.txt
```

Open a database in IDA and wait for initial analysis. The plugin starts its
per-instance MCP server automatically when the gateway is enabled.

## Gateway And CLI

```bash
# Start the standalone gateway
python ida_mcp/command.py gateway start --json

# Status, stop, open IDA, call a tool directly
python ida_mcp/command.py gateway status
python ida_mcp/command.py gateway stop
python ida_mcp/command.py ida open ./target.exe
python ida_mcp/command.py tool call get_metadata --port 10000
```

Default endpoints:

- Gateway MCP proxy: `http://127.0.0.1:11338/mcp`
- Gateway internal API: `http://127.0.0.1:11338/internal/*`
- Direct IDA instance MCP: `http://127.0.0.1:<instance_port>/mcp/`

## Tests

Tests require a running gateway and at least one registered IDA instance.

```bash
python test/test.py
python test/test.py --core --analysis

pytest -m "core or analysis"
pytest -m "not debug"
```

The `debug` marker is excluded by default because it requires an active
debugger. API call logs are written to `.artifacts/api_logs/`.

## Documentation

- `API.md` documents the MCP tools, resources, proxy behavior, and internal HTTP routes.
- `project.md` explains repository responsibilities and module boundaries.
- `roadmap.md` tracks current stabilization work.
