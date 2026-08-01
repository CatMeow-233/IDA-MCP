"""Probe the IDA-MCP gateway's exposed tool list over MCP Streamable HTTP.

Usage: python mcp_probe.py [--tools name,...] [--call name --args '{"json":...}']
"""
import argparse
import json
import sys
import urllib.request

BASE = "http://127.0.0.1:11338/mcp"
TOKEN = "t3uEchUXsE7EcfiVbzscJEHQ7TVB6rTWjvLy1PyMTtw"


def rpc(payload, session_id=None, headers=None):
    req_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {TOKEN}",
    }
    if session_id:
        req_headers["Mcp-Session-Id"] = session_id
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(
        BASE, data=json.dumps(payload).encode(), headers=req_headers, method="POST"
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        sid = resp.headers.get("Mcp-Session-Id")
        body = resp.read().decode()
        return sid, body


def parse_body(body):
    """Handle both pure JSON and SSE-formatted responses."""
    text = body.strip()
    if text.startswith("{"):
        return json.loads(text)
    # SSE: lines like 'event: message' / 'data: {...}'
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            data = line[5:].strip()
            if data and data != "[DONE]":
                return json.loads(data)
    return {"error": "no data frame", "raw": text[:500]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", help="comma-separated tool names to check presence of")
    ap.add_argument("--call", help="tool name to call")
    ap.add_argument("--args", default="{}", help='JSON args for --call, e.g. \'{"port":10000}\'')
    args = ap.parse_args()

    if args.args.startswith("@"):
        with open(args.args[1:], "r", encoding="utf-8") as fh:
            args.args = fh.read()

    sid, body = rpc({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "probe", "version": "0.1"},
        },
    })
    print("[initialize]", body[:300].replace("\n", " "))
    sid, body = rpc({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {},
    }, session_id=sid)
    print("[initialized] ok, session:", sid)

    if args.call:
        sid, body = rpc({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": args.call, "arguments": json.loads(args.args)},
        }, session_id=sid)
        print(f"[call {args.call}] {body[:2000]}")
        return

    sid, body = rpc({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    }, session_id=sid)
    parsed = parse_body(body)
    tools = parsed.get("result", {}).get("tools", [])
    names = sorted(t["name"] for t in tools)
    print(f"[tools/list] total={len(tools)}")
    if args.tools:
        wanted = [t.strip() for t in args.tools.split(",") if t.strip()]
        for w in wanted:
            print(("FOUND    " if w in names else "MISSING  ") + w)
    else:
        for n in names:
            print(" ", n)


if __name__ == "__main__":
    main()
