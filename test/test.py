#!/usr/bin/env python
"""IDA-MCP test main entrypoint.

Usage:
    python test/test.py                 # Run all tests (excluding debug)
    python test/test.py --all           # Run all tests (including debug)

    # Run by module:
    python test/test.py --core          # Core module (metadata, functions, imports/exports, etc.)
    python test/test.py --analysis      # Analysis module (decompile, search, basic blocks, etc.)
    python test/test.py --types         # Types module (type declarations, structs, etc.)
    python test/test.py --modify        # Modify module (comments, renames, patches, etc.)
    python test/test.py --modeling      # Modeling module (create functions, convert code/data/string)
    python test/test.py --memory        # Memory module (read bytes/integers/strings)
    python test/test.py --stack         # Stack module (stack-frame variables)
    python test/test.py --debug         # Debug module (debugger, manual configuration required)
    python test/test.py --resources     # Resources module (MCP resources)
    python test/test.py --lifecycle     # Lifecycle module (start/shutdown IDA)

    # Combined usage:
    python test/test.py --core --analysis    # Run core and analysis

    # Direct pytest usage:
    pytest -m core                      # Run core module only
    pytest -m "core or analysis"        # Run core and analysis
    pytest -m "not debug"               # Exclude debug module
    pytest test/test_core.py              # Run specified file
"""
import sys
import os

# Add ida_mcp subproject root to path
IDA_MCP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if IDA_MCP_ROOT not in sys.path:
    sys.path.insert(0, IDA_MCP_ROOT)

# Available module markers
MODULES = ["core", "analysis", "types", "modify", "modeling", "memory", "stack", "debug", "resources", "lifecycle"]

GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 11338
GATEWAY_INTERNAL_BASE = f"http://{GATEWAY_HOST}:{GATEWAY_PORT}/internal"


def check_gateway() -> bool:
    """Check if gateway internal API is available."""
    import urllib.request
    import json

    try:
        url = f"{GATEWAY_INTERNAL_BASE}/healthz"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return bool(isinstance(data, dict) and data.get("ok"))
    except Exception:
        return False


def check_instances_available() -> bool:
    """Check if any registered IDA instances exist."""
    import urllib.request
    import json

    try:
        url = f"{GATEWAY_INTERNAL_BASE}/instances"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            instances = data if isinstance(data, list) else []
            return len(instances) > 0
    except Exception:
        return False


def check_gateway_proxy() -> bool:
    """Check if the gateway MCP proxy is available."""
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((GATEWAY_HOST, GATEWAY_PORT))
        sock.close()
        return result == 0
    except Exception:
        return False


def print_help():
    """Print help message."""
    print(__doc__)
    print("Available modules:")
    for m in MODULES:
        print(f"  --{m}")
    print()


def run_tests(args: list | None = None):
    """Run tests."""
    try:
        import pytest
    except ImportError:
        print("ERROR: pytest not installed. Run: pip install pytest")
        return 1

    # Check gateway / instance availability
    if not check_gateway():
        print(f"WARNING: Gateway internal API not available at {GATEWAY_INTERNAL_BASE}")
        print("Please start IDA and load the MCP plugin first.")
        print()
        response = input("Continue anyway? (y/N): ").strip().lower()
        if response != 'y':
            return 1
    elif not check_instances_available():
        print("WARNING: No IDA instances available.")
        print("Please open a binary in IDA and ensure the MCP plugin is running.")
        print()
        response = input("Continue anyway? (y/N): ").strip().lower()
        if response != 'y':
            return 1

    # Build pytest arguments
    test_dir = os.path.dirname(os.path.abspath(__file__))
    basetemp = os.path.join(IDA_MCP_ROOT, ".artifacts", "pytest_tmp")
    pytest_args = [test_dir, "-v", f"--basetemp={basetemp}"]

    # Collect modules to run
    selected_modules: list[str] = []
    run_all = False
    remaining_args: list[str] = []

    if args:
        for arg in args:
            if arg == "--all":
                run_all = True
            elif arg.startswith("--") and arg[2:] in MODULES:
                selected_modules.append(arg[2:])
            else:
                remaining_args.append(arg)

    if not check_gateway_proxy():
        print(f"WARNING: Gateway proxy not available at {GATEWAY_HOST}:{GATEWAY_PORT}")
        print("Please check config.conf and restart IDA plugin.")
        return 1

    # Build marker expression
    if selected_modules:
        # Run specified modules
        marker_expr = " or ".join(selected_modules)
        pytest_args.extend(["-m", marker_expr])
    elif not run_all:
        # Default excludes debug (debugger needs manual configuration)
        pytest_args.extend(["-m", "not debug"])

    # Pass remaining args to pytest
    pytest_args.extend(remaining_args)

    # Show tests to be run
    print(f"Running: pytest {' '.join(pytest_args[1:])}")
    print()

    # Run tests
    return pytest.main(pytest_args)


def main():
    """Main function."""
    args = sys.argv[1:]

    if "--help" in args or "-h" in args:
        print_help()
        return 0

    return run_tests(args)


if __name__ == "__main__":
    sys.exit(main())
