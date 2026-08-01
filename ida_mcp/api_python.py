"""Python execution API - execute arbitrary Python code in the IDA context.

Provides tools:
    - py_eval    execute Python code in the IDA context
"""
from __future__ import annotations

import ast
import contextlib
import io
import traceback
from typing import Annotated

from .rpc import tool, unsafe
from .sync import idawrite

# IDA module imports
try:
    import idaapi  # type: ignore
    import ida_bytes  # type: ignore
    import ida_funcs  # type: ignore
    import ida_hexrays  # type: ignore
    import ida_kernwin  # type: ignore
    import ida_nalt  # type: ignore
    import ida_name  # type: ignore
    import ida_segment  # type: ignore
    import ida_typeinf  # type: ignore
    import ida_xref  # type: ignore
    import ida_entry  # type: ignore
    import ida_frame  # type: ignore
    import ida_lines  # type: ignore
    import ida_ida  # type: ignore
except ImportError:
    idaapi = None
    ida_bytes = None
    ida_funcs = None
    ida_hexrays = None
    ida_kernwin = None
    ida_nalt = None
    ida_name = None
    ida_segment = None
    ida_typeinf = None
    ida_xref = None
    ida_entry = None
    ida_frame = None
    ida_lines = None
    ida_ida = None


def _lazy_import(module_name: str):
    """Lazily import an IDA module, returning None on failure."""
    try:
        return __import__(module_name)
    except Exception:
        return None


@unsafe
@tool
@idawrite
def py_eval(
    code: Annotated[str, "Python code to execute in IDA context"],
) -> dict:
    """Execute Python code in IDA context.
    Returns dict with result/stdout/stderr.
    Has access to all IDA API modules.
    Supports Jupyter-style evaluation (last expression is returned).
    Code runs in a single module-like namespace: functions/closures see
    top-level variables and `import ... as` aliases bind normally."""
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    try:
        with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
            from .utils import parse_address, hex_addr

            exec_globals = {
                "__builtins__": __builtins__,
                "idaapi": idaapi,
                "idautils": _lazy_import("idautils"),
                "ida_allins": _lazy_import("ida_allins"),
                "ida_auto": _lazy_import("ida_auto"),
                "ida_bytes": ida_bytes,
                "ida_dbg": _lazy_import("ida_dbg"),
                "ida_entry": ida_entry,
                "ida_expr": _lazy_import("ida_expr"),
                "ida_frame": ida_frame,
                "ida_funcs": ida_funcs,
                "ida_gdl": _lazy_import("ida_gdl"),
                "ida_graph": _lazy_import("ida_graph"),
                "ida_hexrays": ida_hexrays,
                "ida_ida": ida_ida,
                "ida_idd": _lazy_import("ida_idd"),
                "ida_idp": _lazy_import("ida_idp"),
                "ida_kernwin": ida_kernwin,
                "ida_lines": ida_lines,
                "ida_loader": _lazy_import("ida_loader"),
                "ida_nalt": ida_nalt,
                "ida_name": ida_name,
                "ida_netnode": _lazy_import("ida_netnode"),
                "ida_pro": _lazy_import("ida_pro"),
                "ida_search": _lazy_import("ida_search"),
                "ida_segment": ida_segment,
                "ida_strlist": _lazy_import("ida_strlist"),
                "ida_typeinf": ida_typeinf,
                "ida_ua": _lazy_import("ida_ua"),
                "ida_xref": ida_xref,
                "ida_enum": _lazy_import("ida_enum"),
                "parse_address": parse_address,
                "hex_addr": hex_addr,
            }

            result_value = None
            # 单一命名空间（globals 兼 locals）：函数闭包能读到顶层变量，
            # import ... as 别名在后续 eval 里也能正常绑定——与模块执行语义一致。
            ns = exec_globals

            try:
                tree = ast.parse(code)
            except SyntaxError:
                exec(code, ns)
                if "result" in ns:
                    result_value = str(ns["result"])
            else:
                if not tree.body:
                    pass
                elif len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr):
                    result_value = str(eval(code, ns))
                elif isinstance(tree.body[-1], ast.Expr):
                    if len(tree.body) > 1:
                        exec_tree = ast.Module(body=tree.body[:-1], type_ignores=[])
                        exec(compile(exec_tree, "<string>", "exec"), ns)
                    eval_tree = ast.Expression(body=tree.body[-1].value)
                    result_value = str(
                        eval(compile(eval_tree, "<string>", "eval"), ns)
                    )
                else:
                    before = set(ns)
                    exec(code, ns)
                    if "result" in ns:
                        result_value = str(ns["result"])
                    else:
                        new_keys = [k for k in ns if k not in before]
                        if new_keys:
                            result_value = str(ns[new_keys[-1]])

        stdout_text = stdout_capture.getvalue()
        stderr_text = stderr_capture.getvalue()

        return {
            "result": result_value or "",
            "stdout": stdout_text,
            "stderr": stderr_text,
        }

    except Exception:
        return {
            "result": "",
            "stdout": stdout_capture.getvalue(),
            "stderr": traceback.format_exc(),
        }
