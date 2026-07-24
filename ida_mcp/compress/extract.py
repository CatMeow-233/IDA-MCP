"""SEMZ 压缩文本块切片（纯 Python，无 IDA 依赖）。

从 compress_function/compress_text 产出的压缩文本中，按 Ln 标签切出
指定基本块的原文行，供 deflat 流程给块分析子代理准备分片 prompt。
标签按地址序确定性分配，重跑同函数压缩结果一致，可安全按标签寻址。
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Sequence

_LABEL_LINE_RE = re.compile(r"^(L\d+):")


def parse_blocks(text: str) -> Dict[str, List[str]]:
    """压缩文本 → {label: [指令行...]}（不含标签行本身；头部行忽略）。"""
    blocks: Dict[str, List[str]] = {}
    cur: Optional[str] = None
    for ln in text.splitlines():
        m = _LABEL_LINE_RE.match(ln)
        if m:
            cur = m.group(1)
            blocks.setdefault(cur, [])
            continue
        if cur is None:
            continue  # 头部行（#SZ1/#K/#P/#J/#f / #SEMZ1/#MN/...）
        if ln.strip():
            blocks[cur].append(ln)
    return blocks


def header_lines(text: str) -> List[str]:
    """压缩文本的头部行（第一个标签行之前的 #SZ1/#K/#P/#J/#f 等）。"""
    out: List[str] = []
    for ln in text.splitlines():
        if _LABEL_LINE_RE.match(ln):
            break
        if ln.strip():
            out.append(ln)
    return out


def extract_blocks(text: str, labels: Sequence[str]) -> dict:
    """按标签切出块体。

    Returns:
        成功: {"header": [...], "blocks": {label: [...]}, "missing": []}
        任一标签不存在: {"error": ..., "available": [...]}
    """
    blocks = parse_blocks(text)
    missing = [lb for lb in labels if lb not in blocks]
    if missing:
        return {
            "error": f"labels not found: {', '.join(missing)}",
            "available": sorted(blocks, key=lambda s: int(s[1:])),
        }
    return {
        "header": header_lines(text),
        "blocks": {lb: blocks[lb] for lb in labels},
        "missing": [],
    }


def format_blocks(extracted: dict, with_header: bool = True) -> str:
    """把 extract_blocks 结果重新拼成压缩文本片段（保持原始行格式）。"""
    lines: List[str] = []
    if with_header:
        lines.extend(extracted.get("header") or [])
    for label, blk_lines in (extracted.get("blocks") or {}).items():
        lines.append(f"{label}:")
        lines.extend(blk_lines)
    return "\n".join(lines) + "\n"
