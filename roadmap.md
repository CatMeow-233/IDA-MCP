# IDA-MCP Roadmap

## Current Baseline

- IDA 9.x-oriented plugin entry point and per-instance FastMCP server.
- Standalone gateway with internal HTTP routes and MCP proxy endpoint.
- Core analysis, memory, modeling, modify, stack, type, debug, Python, and resource APIs.
- CLI control surface through `ida_mcp/command.py`.
- Live-IDA pytest suite under `test/`.

## Priorities

### P0: Standalone Repository Stabilization

- Keep this repository focused on the IDA plugin and gateway only.
- Keep `ida-plugin.json`, `README.md`, `API.md`, `project.md`, and `roadmap.md` in standalone-repo form.
- Keep Sarma integration through Git submodule boundaries.
- Remove stale `ide/resources/ida_mcp` path assumptions from tests and docs.

### P1: Contract Stability

- Stabilize `/internal`, proxy tools, direct instance tools, and `ida://` resources.
- Document request and response shapes in `API.md`.
- Make errors consistent across CLI, internal HTTP, MCP tools, and resources.

### P2: Multi-Instance Reliability

- Harden heartbeat, unresponsive instance handling, and shutdown behavior.
- Clarify concurrent call and timeout semantics.
- Improve instance selection and recovery behavior in the gateway proxy.

### P3: Resource And Browsing Depth

- Expand `ida://` resource coverage.
- Improve pagination, filtering, and large response behavior.
- Keep read-only browsing APIs clearly separated from mutating tools.

### P4: Testing

- Broaden gateway, proxy, lifecycle, and resource test coverage.
- Keep debug tests opt-in.
- Maintain fixture coverage for representative IDA 9.x databases.

## Non-Goals

- Do not place PySide6 UI, workspace persistence, chat state, or Sarma workflow code in this repository.
- Do not make `ida_mcp` depend on Sarma.
- Do not expand unsafe tools without explicit config gating and documentation.
