"""Debugger API - debugger controls (unsafe).

Provides tools:
    - dbg_regs  get registers
    - dbg_callstack  get call stack
    - dbg_list_bps  list breakpoints
    - dbg_start  start debugger
    - dbg_exit  exit debugger
    - dbg_continue  continue execution
    - dbg_run_to  run to address
    - dbg_add_bp  add breakpoint
    - dbg_delete_bp  delete breakpoint
    - dbg_enable_bp  enable/disable breakpoint
    - dbg_step_into  step into
    - dbg_step_over  step over
    - dbg_read_mem  read debug memory
    - dbg_write_mem  write debug memory
"""
from __future__ import annotations

from typing import Annotated, Optional, List, Dict, Any, Union

from .rpc import tool, unsafe
from .sync import idaread, idawrite
from .utils import parse_address, normalize_list_input, hex_addr

# IDA module imports
try:
    import idaapi  # type: ignore
    import ida_funcs  # type: ignore
    import ida_dbg  # type: ignore
except ImportError:
    idaapi = None
    ida_funcs = None
    ida_dbg = None

_MAX_DEBUG_REGIONS = 64
_MAX_DEBUG_MEMORY_BYTES = 4096
_MAX_DEBUG_TOTAL_BYTES = 1024 * 1024


def _breakpoint_exists(address: int) -> bool:
    try:
        if hasattr(ida_dbg, 'get_bpt_flags'):
            return ida_dbg.get_bpt_flags(address) != -1  # type: ignore
    except Exception:
        pass
    return False


def _delete_breakpoint(address: int) -> bool:
    try:
        if hasattr(ida_dbg, 'del_bpt'):
            return bool(ida_dbg.del_bpt(address))
    except Exception:
        pass
    return False

def _wait_for_debugger_event(timeout_ms: int = 1000) -> bool:
    """Wait for debugger events and handle them. Returns whether the debugger is suspended."""
    import time
    
    start = time.time()
    timeout_sec = timeout_ms / 1000.0
    
    while (time.time() - start) < timeout_sec:
        try:
            # try waiting for a debugger event
            if hasattr(ida_dbg, 'wait_for_next_event'):
                # briefly wait for event (10ms)
                event = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 10)
                if event:
                    return True
            
            # check debugger state
            if ida_dbg.is_debugger_on():
                # try reading a register to verify the debugger is actually usable
                try:
                    rip = ida_dbg.get_reg_val("RIP")
                    if rip is not None:
                        return True
                    rip = ida_dbg.get_reg_val("EIP")
                    if rip is not None:
                        return True
                except Exception:
                    pass
            
            time.sleep(0.05)
        except Exception:
            time.sleep(0.05)
    
    return False


# ============================================================================
# Registers
# ============================================================================

@unsafe
@tool
@idaread
def dbg_regs() -> dict:
    """Get all debugger registers (requires active debugger)."""
    try:
        if not ida_dbg.is_debugger_on():
            return {"ok": False, "registers": [], "note": "debugger not active"}
    except Exception:
        return {"error": "cannot determine debugger state"}
    
    regs: List[dict] = []
    names: List[str] = []
    notes: List[str] = []
    
    # try to get register names
    try:
        if hasattr(ida_dbg, 'get_dbg_reg_names'):
            names = list(ida_dbg.get_dbg_reg_names())  # type: ignore
    except Exception as e:
        notes.append(f"get_dbg_reg_names: {e}")
    
    # if no names available, fall back to common x64 registers
    if not names:
        names = ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", 
                 "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
                 "RIP", "RFLAGS", "CS", "SS", "DS", "ES", "FS", "GS"]
        notes.append("using hardcoded x64 register names")
    
    for n in names:
        try:
            v = ida_dbg.get_reg_val(n)
            if v is None:
                continue
            if isinstance(v, int):
                bits = 8
                if v > 0xFFFFFFFF:
                    bits = 64
                elif v > 0xFFFF:
                    bits = 32
                elif v > 0xFF:
                    bits = 16
                width = bits // 4
                regs.append({"name": n, "value": f"0x{v:0{width}X}", "int": int(v)})
            else:
                regs.append({"name": n, "value": repr(v)})
        except Exception:
            continue
    
    result: dict = {"ok": True, "registers": regs}
    if notes:
        result["notes"] = notes
    if not regs:
        result["note"] = "no registers retrieved (process may be running)"
    
    return result


# ============================================================================
# Call stack
# ============================================================================

@unsafe
@tool
@idaread
def dbg_callstack() -> dict:
    """Get current call stack (requires active debugger)."""
    try:
        if not ida_dbg.is_debugger_on():
            return {"ok": False, "frames": [], "note": "debugger not active"}
    except Exception:
        return {"error": "cannot determine debugger state"}
    
    frames: List[dict] = []
    collected = False
    
    # prefer official API
    try:
        if hasattr(ida_dbg, 'get_call_stack'):
            stk = ida_dbg.get_call_stack()  # type: ignore
            for idx, item in enumerate(stk or []):
                try:
                    ea = int(getattr(item, 'ea', 0))
                    func_name = None
                    try:
                        f = ida_funcs.get_func(ea)
                        if f:
                            func_name = idaapi.get_func_name(f.start_ea)
                    except Exception:
                        func_name = None
                    frames.append({
                        'index': idx,
                        'ea': ea,
                        'func': func_name,
                    })
                except Exception:
                    continue
            if frames:
                collected = True
    except Exception:
        pass
    
    # fallback: walk_stack
    if not collected:
        try:
            if hasattr(ida_dbg, 'walk_stack'):
                def _cb(entry):
                    try:
                        ea = int(getattr(entry, 'ea', 0))
                        func_name = None
                        try:
                            f = ida_funcs.get_func(ea)
                            if f:
                                func_name = idaapi.get_func_name(f.start_ea)
                        except Exception:
                            func_name = None
                        frames.append({
                            'index': len(frames),
                            'ea': ea,
                            'func': func_name,
                        })
                    except Exception:
                        return False
                    return True
                ida_dbg.walk_stack(_cb)  # type: ignore
                if frames:
                    collected = True
        except Exception:
            pass
    
    if not collected:
        return {"ok": False, "frames": [], "note": "call stack API unavailable or empty"}
    
    return {"ok": True, "frames": frames}


# ============================================================================
# Breakpoints
# ============================================================================

@unsafe
@tool
@idaread
def dbg_list_bps() -> dict:
    """List all breakpoints (works without active debugger)."""
    # note: breakpoints can exist while the debugger is not running, so skip is_debugger_on() check
    bps: List[dict] = []
    qty = 0
    
    try:
        qty = ida_dbg.get_bpt_qty()
    except Exception:
        qty = 0
    
    for i in range(qty):
        try:
            ea = ida_dbg.get_bpt_ea(i)  # type: ignore
        except Exception:
            continue
        if ea in (None, idaapi.BADADDR):
            continue
        
        info: dict = {'ea': int(ea)}
        
        # flags / enabled
        flags = None
        try:
            if hasattr(ida_dbg, 'get_bpt_attr'):
                flags = ida_dbg.get_bpt_attr(ea, ida_dbg.BPTATTR_FLAGS)  # type: ignore
            elif hasattr(ida_dbg, 'get_bpt_flags'):
                flags = ida_dbg.get_bpt_flags(ea)  # type: ignore
        except Exception:
            flags = None
        
        enabled = None
        try:
            if flags is not None and hasattr(ida_dbg, 'BPT_ENABLED'):
                enabled = bool(flags & ida_dbg.BPT_ENABLED)  # type: ignore
        except Exception:
            enabled = None
        if enabled is not None:
            info['enabled'] = enabled
        
        # size
        try:
            if hasattr(ida_dbg, 'get_bpt_attr'):
                sz = ida_dbg.get_bpt_attr(ea, ida_dbg.BPTATTR_SIZE)  # type: ignore
                if isinstance(sz, int) and sz > 0:
                    info['size'] = int(sz)
        except Exception:
            pass
        
        # type
        try:
            if hasattr(ida_dbg, 'get_bpt_attr'):
                tp = ida_dbg.get_bpt_attr(ea, ida_dbg.BPTATTR_TYPE)  # type: ignore
                if isinstance(tp, int):
                    info['type'] = int(tp)
        except Exception:
            pass
        
        bps.append(info)
    
    return {"ok": True, "total": len(bps), "breakpoints": bps}


# ============================================================================
# Debug control
# ============================================================================

@unsafe
@tool
@idawrite
def dbg_start() -> dict:
    """Start debugger process (debugger type should be configured manually in IDA)."""
    try:
        if ida_dbg.is_debugger_on():
            return {"ok": True, "started": False, "note": "debugger already running"}
    except Exception:
        pass
    
    try:
        path = idaapi.get_input_file_path()
    except Exception:
        path = None
    if not path:
        return {"error": "cannot determine input file path"}
    
    # start process
    try:
        started = ida_dbg.start_process(path, '', '')  # type: ignore
    except Exception as e:
        return {"error": f"start_process failed: {e}"}
    
    ok = bool(started)
    pid = None
    suspended = False
    
    if ok:
        try:
            state = ida_dbg.get_process_state()
            if state:
                pid = getattr(state, 'pid', None)
        except Exception:
            pid = None
        
        # wait for debugger to suspend
        suspended = _wait_for_debugger_event(2000)
        
        if not suspended:
            try:
                if ida_dbg.is_debugger_on():
                    suspended = True
            except Exception:
                pass
    
    return {"ok": ok, "started": ok, "pid": pid, "suspended": suspended}


@unsafe
@tool
@idawrite
def dbg_exit() -> dict:
    """Exit debugger."""
    try:
        if not ida_dbg.is_debugger_on():
            return {"ok": False, "exited": False, "note": "debugger not active"}
    except Exception:
        return {"error": "cannot determine debugger state"}
    
    try:
        ida_dbg.exit_process()
    except Exception as e:
        return {"error": f"exit_process failed: {e}"}
    
    return {"ok": True, "exited": True}


@unsafe
@tool
@idawrite
def dbg_continue() -> dict:
    """Continue execution."""
    try:
        if not ida_dbg.is_debugger_on():
            return {"ok": False, "continued": False, "note": "debugger not active"}
    except Exception:
        return {"error": "cannot determine debugger state"}
    
    cont_ok = False
    errors: List[str] = []
    tried = False
    
    try:
        if hasattr(ida_dbg, 'continue_process'):
            tried = True
            cont_ok = bool(ida_dbg.continue_process())
    except Exception as e:
        errors.append(f"continue_process: {e}")
    
    if not cont_ok:
        try:
            if hasattr(ida_dbg, 'continue_execution'):
                tried = True
                cont_ok = bool(ida_dbg.continue_execution())  # type: ignore
        except Exception as e:
            errors.append(f"continue_execution: {e}")
    
    if not tried:
        return {"error": "no continue API available"}
    if not cont_ok and errors:
        return {"ok": False, "continued": False, "note": "; ".join(errors)[:200]}
    
    return {"ok": True, "continued": bool(cont_ok)}


@unsafe
@tool
@idawrite
def dbg_run_to(
    addr: Annotated[Union[int, str], "Target address to run to"],
) -> dict:
    """Run debugger to specific address."""
    parsed = parse_address(addr)
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid address"}
    
    address = parsed["value"]
    
    try:
        if not ida_dbg.is_debugger_on():
            return {"error": "debugger not active"}
    except Exception:
        return {"error": "cannot determine debugger state"}
    
    if int(address) == idaapi.BADADDR:
        return {"error": "BADADDR"}
    
    requested = False
    used_temp_bpt = False
    notes: List[str] = []
    
    # try request_run_to
    try:
        if hasattr(ida_dbg, 'request_run_to'):
            requested = bool(ida_dbg.request_run_to(address))
            if not requested:
                notes.append('request_run_to returned False')
        else:
            notes.append('request_run_to unavailable')
    except Exception as e:
        notes.append(f'request_run_to error: {e}')
    
    # fallback: set temporary breakpoint
    if not requested:
        try:
            has_bp = _breakpoint_exists(address)
            
            if not has_bp and hasattr(ida_dbg, 'add_bpt'):
                try:
                    added = False
                    if hasattr(ida_dbg, 'BPT_DEFAULT'):
                        added = bool(ida_dbg.add_bpt(address, 0, ida_dbg.BPT_DEFAULT))  # type: ignore
                    if not added:
                        added = bool(ida_dbg.add_bpt(address, 0))
                    if not added:
                        added = bool(ida_dbg.add_bpt(address))
                    used_temp_bpt = bool(added)
                except Exception as e:
                    notes.append(f'add_bpt error: {e}')
        except Exception:
            notes.append('temp breakpoint fallback failed')
    
    # continue execution
    continued = False
    suspended = False
    cleaned_temp_bpt = None
    try:
        if hasattr(ida_dbg, 'continue_process'):
            continued = bool(ida_dbg.continue_process())
        elif hasattr(ida_dbg, 'continue_execution'):
            continued = bool(ida_dbg.continue_execution())  # type: ignore
        else:
            notes.append('no continue API')
    except Exception as e:
        notes.append(f'continue error: {e}')

    if used_temp_bpt:
        if continued:
            suspended = _wait_for_debugger_event(2000)
            if not suspended:
                notes.append('timed out waiting for temporary breakpoint to trigger')
        else:
            notes.append('continue failed after creating temporary breakpoint')
        cleaned_temp_bpt = _delete_breakpoint(address)
        if not cleaned_temp_bpt and _breakpoint_exists(address):
            notes.append('failed to clean temporary breakpoint')
    
    ok = requested or used_temp_bpt
    result: dict = {
        'ok': ok,
        'requested': requested,
        'continued': continued,
        'suspended': suspended if used_temp_bpt else None,
        'used_temp_bpt': used_temp_bpt,
        'cleaned_temp_bpt': cleaned_temp_bpt,
    }
    if notes:
        result['note'] = '; '.join(notes)[:300]
    
    return result


# ============================================================================
# Breakpoint operations
# ============================================================================

@unsafe
@tool
@idawrite
def dbg_add_bp(
    addr: Annotated[Union[int, str], "Address(es) for breakpoint - single or comma-separated"],
) -> List[dict]:
    """Add breakpoint(s) at address(es)."""
    queries = normalize_list_input(addr)
    results = []
    
    for query in queries:
        result = _set_breakpoint_single(query)
        results.append(result)
    
    return results


def _set_breakpoint_single(query: str) -> dict:
    """Set a single breakpoint."""
    parsed = parse_address(query)
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid address", "query": query}
    
    address = parsed["value"]
    if int(address) == idaapi.BADADDR:
        return {"error": "BADADDR", "query": query}
    
    notes: List[str] = []
    existed = False
    
    try:
        existed = _breakpoint_exists(address)
    except Exception:
        existed = False
    
    added = False
    if not existed:
        try:
            if hasattr(ida_dbg, 'add_bpt'):
                if hasattr(ida_dbg, 'BPT_DEFAULT'):
                    added = bool(ida_dbg.add_bpt(address, 0, ida_dbg.BPT_DEFAULT))  # type: ignore
                if not added:
                    try:
                        added = bool(ida_dbg.add_bpt(address, 0))
                    except Exception:
                        pass
                if not added:
                    try:
                        added = bool(ida_dbg.add_bpt(address))
                    except Exception:
                        pass
            if not added and hasattr(ida_dbg, 'set_bpt'):
                try:
                    added = bool(ida_dbg.set_bpt(address))  # type: ignore
                except Exception as e:
                    notes.append(f'set_bpt error: {e}')
        except Exception as e:
            notes.append(f'add_bpt error: {e}')
    
    ok = existed or added
    result: dict = {
        'query': query,
        'ok': ok,
        'ea': int(address),
        'existed': bool(existed and not added),
        'added': bool(added),
    }
    if notes:
        result['note'] = '; '.join(notes)[:300]
    
    return result


@unsafe
@tool
@idawrite
def dbg_delete_bp(
    addr: Annotated[Union[int, str], "Address(es) - single or comma-separated"],
) -> List[dict]:
    """Delete breakpoint(s) at address(es)."""
    queries = normalize_list_input(addr)
    results = []
    
    for query in queries:
        result = _delete_breakpoint_single(query)
        results.append(result)
    
    return results


def _delete_breakpoint_single(query: str) -> dict:
    """Delete a single breakpoint."""
    parsed = parse_address(query)
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid address", "query": query}
    
    address = parsed["value"]
    if int(address) == idaapi.BADADDR:
        return {"error": "BADADDR", "query": query}
    
    notes: List[str] = []
    existed = False
    
    try:
        existed = _breakpoint_exists(address)
    except Exception:
        existed = False
    
    deleted = False
    if existed:
        try:
            if hasattr(ida_dbg, 'del_bpt'):
                deleted = _delete_breakpoint(address)
            else:
                notes.append('no del_bpt API')
        except Exception as e:
            notes.append(f'del_bpt error: {e}')
    
    ok = not existed or deleted
    result: dict = {
        'query': query,
        'ok': ok,
        'ea': int(address),
        'existed': bool(existed),
        'deleted': bool(deleted),
    }
    if notes:
        result['note'] = '; '.join(notes)[:300]
    
    return result


@unsafe
@tool
@idawrite
def dbg_enable_bp(
    items: Annotated[List[Dict[str, Any]], "List of {address, enable: bool}"],
) -> List[dict]:
    """Enable or disable breakpoint(s)."""
    results = []
    
    for item in items:
        addr = item.get("address")
        enable = item.get("enable", True)
        
        if addr is None:
            results.append({"error": "invalid address", "item": item})
            continue
        
        parsed = parse_address(addr)
        if not parsed["ok"] or parsed["value"] is None:
            results.append({"error": "invalid address", "item": item})
            continue
        
        address = parsed["value"]
        result = _enable_breakpoint_single(address, enable)
        results.append(result)
    
    return results


def _enable_breakpoint_single(address: int, enable: bool) -> dict:
    """Enable or disable a single breakpoint."""
    if int(address) == idaapi.BADADDR:
        return {"error": "BADADDR"}
    
    notes: List[str] = []
    existed = False
    flags = None
    
    try:
        if hasattr(ida_dbg, 'get_bpt_flags'):
            flags = ida_dbg.get_bpt_flags(address)  # type: ignore
            existed = flags != -1
    except Exception:
        existed = False
    
    changed = False
    
    # if enabling and breakpoint does not exist -> create it
    if enable and not existed:
        try:
            added = False
            if hasattr(ida_dbg, 'add_bpt'):
                if hasattr(ida_dbg, 'BPT_DEFAULT'):
                    added = bool(ida_dbg.add_bpt(address, 0, ida_dbg.BPT_DEFAULT))  # type: ignore
                if not added:
                    added = bool(ida_dbg.add_bpt(address, 0))
            if added:
                existed = True
                changed = True
        except Exception as e:
            notes.append(f'add_bpt error: {e}')
    
    # toggle enabled state
    if existed:
        try:
            if hasattr(ida_dbg, 'enable_bpt'):
                ok = ida_dbg.enable_bpt(address, enable)
                if ok:
                    changed = True
        except Exception as e:
            notes.append(f'enable_bpt error: {e}')
    
    # read final state
    enabled_now = enable if existed else False
    try:
        if hasattr(ida_dbg, 'get_bpt_flags'):
            flags2 = ida_dbg.get_bpt_flags(address)  # type: ignore
            if flags2 is not None and flags2 != -1 and hasattr(ida_dbg, 'BPT_ENABLED'):
                enabled_now = bool(flags2 & ida_dbg.BPT_ENABLED)  # type: ignore
    except Exception:
        pass
    
    result: dict = {
        'ok': existed,
        'ea': int(address),
        'existed': bool(existed),
        'enabled': bool(enabled_now),
        'changed': bool(changed),
    }
    if notes:
        result['note'] = '; '.join(notes)[:300]
    
    return result


# ============================================================================
# Single stepping
# ============================================================================

@unsafe
@tool
@idawrite
def dbg_step_into() -> dict:
    """Step into instruction."""
    try:
        if not ida_dbg.is_debugger_on():
            return {"ok": False, "stepped": False, "note": "debugger not active"}
    except Exception:
        return {"error": "cannot determine debugger state"}
    
    step_ok = False
    errors: List[str] = []
    tried = False
    
    try:
        if hasattr(ida_dbg, 'step_into'):
            tried = True
            step_ok = bool(ida_dbg.step_into())
    except Exception as e:
        errors.append(f"step_into: {e}")
    
    if not step_ok and not tried:
        try:
            if hasattr(ida_dbg, 'request_step_into'):
                tried = True
                step_ok = bool(ida_dbg.request_step_into())
        except Exception as e:
            errors.append(f"request_step_into: {e}")
    
    if not tried:
        return {"error": "no step_into API available"}
    if not step_ok and errors:
        return {"ok": False, "stepped": False, "note": "; ".join(errors)[:200]}
    
    return {"ok": True, "stepped": bool(step_ok)}


@unsafe
@tool
@idawrite
def dbg_step_over() -> dict:
    """Step over instruction."""
    try:
        if not ida_dbg.is_debugger_on():
            return {"ok": False, "stepped": False, "note": "debugger not active"}
    except Exception:
        return {"error": "cannot determine debugger state"}
    
    step_ok = False
    errors: List[str] = []
    tried = False
    
    try:
        if hasattr(ida_dbg, 'step_over'):
            tried = True
            step_ok = bool(ida_dbg.step_over())
    except Exception as e:
        errors.append(f"step_over: {e}")
    
    if not step_ok and not tried:
        try:
            if hasattr(ida_dbg, 'request_step_over'):
                tried = True
                step_ok = bool(ida_dbg.request_step_over())
        except Exception as e:
            errors.append(f"request_step_over: {e}")
    
    if not tried:
        return {"error": "no step_over API available"}
    if not step_ok and errors:
        return {"ok": False, "stepped": False, "note": "; ".join(errors)[:200]}
    
    return {"ok": True, "stepped": bool(step_ok)}


# ============================================================================
# Debug memory operations
# ============================================================================

@unsafe
@tool
@idaread
def dbg_read_mem(
    regions: Annotated[List[Dict[str, Any]], "List of {address, size}"],
) -> List[dict]:
    """Read memory from debugged process."""
    try:
        if not ida_dbg.is_debugger_on():
            return [{"error": "debugger not active"}]
    except Exception:
        return [{"error": "cannot determine debugger state"}]
    
    if not isinstance(regions, list):
        return [{"error": "regions must be a list"}]
    if len(regions) > _MAX_DEBUG_REGIONS:
        return [{"error": f"too many regions (max {_MAX_DEBUG_REGIONS})"}]

    results = []
    total_requested = 0
    
    for region in regions:
        if not isinstance(region, dict):
            results.append({"error": "region must be an object", "region": region})
            continue
        addr = region.get("address")
        size = region.get("size", 16)
        
        if addr is None:
            results.append({"error": "invalid address", "region": region})
            continue
        
        parsed = parse_address(addr)
        if not parsed["ok"] or parsed["value"] is None:
            results.append({"error": "invalid address", "region": region})
            continue
        
        address = parsed["value"]
        if not isinstance(size, int):
            results.append({"error": "size must be an integer", "address": hex_addr(address)})
            continue
        if size <= 0:
            results.append({"error": "size must be > 0", "address": hex_addr(address)})
            continue
        if size > _MAX_DEBUG_MEMORY_BYTES:
            results.append({"error": f"size too large (max {_MAX_DEBUG_MEMORY_BYTES})", "address": hex_addr(address)})
            continue
        total_requested += size
        if total_requested > _MAX_DEBUG_TOTAL_BYTES:
            results.append({"error": f"total read too large (max {_MAX_DEBUG_TOTAL_BYTES})", "address": hex_addr(address)})
            continue
        
        try:
            data = ida_dbg.read_dbg_memory(address, size)  # type: ignore
            if data is None:
                results.append({"error": "failed to read", "address": hex_addr(address)})
                continue
            
            byte_list = list(data)
            hex_str = ' '.join(f'{b:02X}' for b in byte_list)
            
            results.append({
                "address": hex_addr(address),
                "size": len(byte_list),
                "bytes": byte_list,
                "hex": hex_str,
            })
        except Exception as e:
            results.append({"error": str(e), "address": hex_addr(address)})
    
    return results


@unsafe
@tool
@idawrite
def dbg_write_mem(
    regions: Annotated[List[Dict[str, Any]], "List of {address, bytes: [int,...]}"],
) -> List[dict]:
    """Write memory to debugged process."""
    try:
        if not ida_dbg.is_debugger_on():
            return [{"error": "debugger not active"}]
    except Exception:
        return [{"error": "cannot determine debugger state"}]
    
    if not isinstance(regions, list):
        return [{"error": "regions must be a list"}]
    if len(regions) > _MAX_DEBUG_REGIONS:
        return [{"error": f"too many regions (max {_MAX_DEBUG_REGIONS})"}]

    results = []
    total_requested = 0
    
    for region in regions:
        if not isinstance(region, dict):
            results.append({"error": "region must be an object", "region": region})
            continue
        addr = region.get("address")
        data = region.get("bytes", [])
        
        if addr is None:
            results.append({"error": "invalid address", "region": region})
            continue
        
        parsed = parse_address(addr)
        if not parsed["ok"] or parsed["value"] is None:
            results.append({"error": "invalid address", "region": region})
            continue
        
        address = parsed["value"]
        if not isinstance(data, list):
            results.append({"error": "bytes must be a list", "address": hex_addr(address)})
            continue
        if len(data) > _MAX_DEBUG_MEMORY_BYTES:
            results.append({"error": f"bytes too long (max {_MAX_DEBUG_MEMORY_BYTES})", "address": hex_addr(address)})
            continue
        total_requested += len(data)
        if total_requested > _MAX_DEBUG_TOTAL_BYTES:
            results.append({"error": f"total write too large (max {_MAX_DEBUG_TOTAL_BYTES})", "address": hex_addr(address)})
            continue
        
        try:
            byte_data = bytes(data)
            written = ida_dbg.write_dbg_memory(address, byte_data)
            
            results.append({
                "address": hex_addr(address),
                "size": len(byte_data),
                "written": written,
            })
        except Exception as e:
            results.append({"error": str(e), "address": hex_addr(address)})
    
    return results
