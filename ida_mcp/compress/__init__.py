"""SEMZ v1 语义压缩核心（纯 Python，禁止顶层 import idaapi/ida_*）。"""
from __future__ import annotations

from .model import CompressError
from .pipeline import compress_insns, compress_text
from .extract import extract_blocks, format_blocks, header_lines, parse_blocks

__all__ = [
    "compress_insns",
    "compress_text",
    "CompressError",
    "extract_blocks",
    "format_blocks",
    "header_lines",
    "parse_blocks",
]
