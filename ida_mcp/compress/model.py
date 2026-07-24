"""SEMZ 语义压缩核心数据模型（纯 Python，禁止 import idaapi/ida_*）。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


class CompressError(Exception):
    """语义压缩管线错误。"""


@dataclass
class Insn:
    """一条指令。ea 为 None 表示输入未提供地址（纯文本流）。"""

    ea: Optional[int]
    mnem: str
    ops: List[str]
    raw: str
    comment: Optional[str] = None


@dataclass
class Block:
    """基本块。label 由 layers.assign_labels 按地址序分配（entry=L0）。"""

    label: str
    ea: Optional[int]
    insns: List[Insn] = field(default_factory=list)
