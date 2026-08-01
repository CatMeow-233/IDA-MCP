"""ida_mcp.emu 纯单元测试（不依赖活 IDA / gateway，conftest 的 fixtures 均为按需注入）。

策略：unicorn 缺失时整文件跳过；指令编码均先用 unicorn 实测反证过（2.1.4）。
"""
from __future__ import annotations

import pytest

pytest.importorskip("unicorn")

from ida_mcp.emu import ABI_PRESETS, ARCHES, available, run

CODE = 0x10000
BUF = 0x20000

# arm64: movz x0, #0x2a ; str x0, [x1] ; ret
ARM64_BASIC = bytes.fromhex("400580D2" "200000F9" "C0035FD6")
# arm64: svc #0 ; movz x0, #7 ; ret
ARM64_SVC = bytes.fromhex("010000D4" "E00080D2" "C0035FD6")
# arm64: b .  （死循环）
ARM64_B_LOOP = bytes.fromhex("00000014")
# arm: mov r0, #0x2a ; str r0, [r1] ; bx lr
ARM_BASIC = bytes.fromhex("2A00A0E3" "000081E5" "1EFF2FE1")
# x64: mov eax, 0x2a ; mov [rdi], eax ; ret
X64_BASIC = bytes.fromhex("B82A000000" "8907" "C3")
# x86: mov eax, 0x2a ; mov [0x20000], eax ; ret
X86_BASIC = bytes.fromhex("B82A000000" "A300000200" "C3")


def test_available_and_tables():
    assert available() is True
    assert set(ARCHES) == {"arm64", "arm", "x64", "x86"}
    assert set(ABI_PRESETS) == {"aapcs64", "aapcs32", "sysv64", "win64", "cdecl"}
    assert ABI_PRESETS["sysv64"]["arg_regs"] == ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
    assert ABI_PRESETS["win64"]["arg_regs"][0] == "rcx"
    assert ABI_PRESETS["cdecl"]["stack_args"] is True
    assert ABI_PRESETS["aapcs64"]["lr_reg"] == "x30"


def test_arm64_basic_write_watch():
    image = {CODE: ARM64_BASIC, BUF: b"\x00" * 0x1000}
    r = run(image, "arm64", CODE, regs={"x1": BUF}, lr_sentinel=True)
    assert r["ok"] is True
    assert r["stop_reason"] == "sentinel"
    assert r["error"] is None
    assert r["fault"] is None
    assert r["regs"]["x0"] == "0x2A"
    rb = [x for x in r["readbacks"] if x["addr"] == "0x20000"]
    assert rb, "readbacks 应覆盖 0x20000 脏页: %r" % (r["readbacks"],)
    assert rb[0]["data"][:8] == (0x2A).to_bytes(8, "little")
    assert any(d["addr"] == "0x20000" for d in r["dirty"])


def test_arm64_stop_at():
    image = {CODE: ARM64_BASIC, BUF: b"\x00" * 0x1000}
    # 注意：str x0,[x1] 在 0x10004（0x10008 是 ret）；命中即停，命中指令不执行
    r = run(image, "arm64", CODE, regs={"x1": BUF}, stop_at=[0x10004])
    assert r["ok"] is True
    assert r["stop_reason"] == "stop_at"
    assert r["pc"] == "0x10004"
    # str 未执行：无脏页、无回读内容
    assert r["dirty"] == []
    assert r["readbacks"] == []
    blob = b"".join(x["data"] for x in r["readbacks"])
    assert (0x2A).to_bytes(8, "little") not in blob


def test_arm64_budget():
    r = run({CODE: ARM64_B_LOOP}, "arm64", CODE, max_instructions=1000)
    assert r["ok"] is True
    assert r["stop_reason"] == "budget"
    assert r["instructions"] == 1000
    assert r["pc"] == "0x10000"  # b . 原地循环


def test_arm64_svc_ret0():
    r = run({CODE: ARM64_SVC}, "arm64", CODE, lr_sentinel=True)
    assert r["ok"] is True
    assert r["stop_reason"] == "sentinel"
    assert len(r["svc_log"]) == 1
    assert r["svc_log"][0]["number"] == 0
    assert r["svc_log"][0]["pc"] == "0x10000"
    # ret0 在 svc 时把 x0 清零，随后 movz x0,#7 覆盖
    assert r["regs"]["x0"] == "0x7"


def test_arm64_svc_trap():
    r = run({CODE: ARM64_SVC}, "arm64", CODE, svc_policy="trap", lr_sentinel=True)
    assert r["ok"] is True
    assert r["stop_reason"] == "svc_trap"
    assert len(r["svc_log"]) == 1
    assert r["svc_log"][0]["number"] == 0


def test_x64_sysv64_abi():
    """sysv64 第一参数寄存器 rdi 非硬编码：buf 经 regs 注入，写入应命中。"""
    image = {CODE: X64_BASIC, BUF: b"\x00" * 0x1000}
    r = run(image, "x64", CODE, regs={"rdi": BUF}, lr_sentinel=True)
    assert r["ok"] is True
    assert r["stop_reason"] == "sentinel"
    assert r["regs"]["rax"] == "0x2A"
    rb = [x for x in r["readbacks"] if x["addr"] == "0x20000"]
    assert rb, "readbacks 应覆盖 0x20000 脏页: %r" % (r["readbacks"],)
    assert int.from_bytes(rb[0]["data"][:4], "little") == 0x2A


def test_arm32_basic():
    image = {CODE: ARM_BASIC, BUF: b"\x00" * 0x1000}
    r = run(image, "arm", CODE, regs={"r1": BUF}, lr_sentinel=True)
    assert r["ok"] is True
    assert r["stop_reason"] == "sentinel"
    assert r["regs"]["r0"] == "0x2A"
    rb = [x for x in r["readbacks"] if x["addr"] == "0x20000"]
    assert rb and int.from_bytes(rb[0]["data"][:4], "little") == 0x2A


def test_x86_basic():
    image = {CODE: X86_BASIC, BUF: b"\x00" * 0x1000}
    r = run(image, "x86", CODE, lr_sentinel=True)
    assert r["ok"] is True
    assert r["stop_reason"] == "sentinel"
    assert r["regs"]["eax"] == "0x2A"
    rb = [x for x in r["readbacks"] if x["addr"] == "0x20000"]
    assert rb and int.from_bytes(rb[0]["data"][:4], "little") == 0x2A


def test_mem_fault_not_auto_mapped():
    # str x0, [x1]，x1=0 → 写未映射地址，不得自动映射，应 mem_fault
    image = {CODE: bytes.fromhex("200000F9")}
    r = run(image, "arm64", CODE, max_instructions=100)
    assert r["ok"] is False
    assert r["stop_reason"] == "mem_fault"
    assert r["fault"]["type"] == "write"
    assert r["fault"]["addr"] == "0x0"
    assert r["fault"]["pc"] == "0x10000"


def test_bad_arch_short_error():
    r = run({}, "mips", CODE)
    assert r["ok"] is False
    assert "unsupported arch" in r["error"]


# x86 cdecl: mov eax, [esp+4] ; add eax, [esp+8] ; ret
X86_CDECL_ADD = bytes.fromhex("8B442404" "03442408" "C3")


def test_x86_cdecl_stack_args():
    """stack_args 补丁：arg0 在 [esp+4]、arg1 在 [esp+8]，哨兵仍正常返回。"""
    image = {CODE: X86_CDECL_ADD}
    r = run(image, "x86", CODE, stack_args=[0x11, 0x22], lr_sentinel=True)
    assert r["ok"] is True
    assert r["stop_reason"] == "sentinel"
    assert r["regs"]["eax"] == "0x33"


def test_reads_unwritten_region():
    """reads 补丁：未被写过（不脏）的区域也能显式回读。"""
    image = {CODE: bytes.fromhex("C0035FD6"), BUF: b"\x00" * 0x1000}  # arm64 ret
    r = run(image, "arm64", CODE, lr_sentinel=True, reads=[(BUF, 16)])
    assert r["ok"] is True
    assert r["dirty"] == []
    rb = [x for x in r["readbacks"] if x["addr"] == "0x20000"]
    assert rb and rb[0]["size"] == 16 and rb[0]["data"] == b"\x00" * 16
