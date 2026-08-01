"""Unicorn 模拟执行运行器（纯 Python 核心，禁止顶层 import idaapi/ida_*）。

架构通用的小函数模拟执行：映射调用方给出的内存映像，布置栈与可选返回哨兵，
从 entry 跑到 stop_at / 哨兵 / 指令预算 / 内存故障 / 异常为止，返回结构化 dict。

unicorn 为可选依赖：导入失败时 available() 返回 False，
run() 返回 {"ok": False, "error": "unicorn not installed: pip install unicorn"}。

unicorn 2.1.x 行为备忘（实测，勿凭直觉改动）：
- ARM64/ARM 的 SVC 触发 UC_HOOK_INTR（intno=2），钩子里 PC 已指向 SVC 的
  下一条指令，钩子返回后从该处继续执行（无需手动跳过）；SVC 号需从 PC-4 处
  的指令编码解出（ARM64: (insn >> 5) & 0xFFFF；ARM: insn & 0xFFFFFF）。
- x86/x64 的 SYSCALL 用 UC_HOOK_INSN 挂钩，钩子里 RIP 指向 SYSCALL 本身，
  钩子返回后 unicorn 自动越过该指令（2 字节）继续执行 —— 不要再手动 RIP+=2，
  否则会多跳 2 字节踩进下一条指令中间。
- UC_HOOK_MEM_INVALID 钩子返回 False 时 emu_start 抛出 UcError，
  钩子内读到的 PC 即故障指令地址；本模块据此归因为 mem_fault。
- UC_HOOK_CODE 在指令执行前触发，但钩子内 emu_stop() 不能阻止当前指令
  执行（副作用已生效，只是 PC 停在钩子地址）。为保证 stop_at/哨兵"命中即停、
  命中指令不执行"，本模块用 emu_start(pc, 0, count=1) 单步驱动执行循环，
  停止判定在循环内完成；代码钩子仅按 max(1, size//4) 近似计量指令数。
- 单步驱动不影响 UC_HOOK_INTR / UC_HOOK_MEM_* 钩子触发（实测），
  单步开销约 1us/指令，默认 20 万指令预算的极端情况亚秒级完成。
- uc.mem_regions() 在 unicorn 2.1.4 + Windows + Python 3.14 下每次调用都会
  触发 "Windows fatal exception: access violation"（进程侥幸存活但 faulthandler
  会刷栈、且有内存损坏风险）。本模块不用它，改为自行维护已映射区间表。
- 同理，每个 Uc 实例的首次 uc_mem_map 会触发一次良性 first-chance
  access violation（unicorn 内部 SEH 捕获后继续，功能正常），但宿主的
  faulthandler（pytest 默认启用）会把它当崩溃刷栈。_mem_map() 在宿主启用
  faulthandler 时临时屏蔽之；未启用时（如 IDA 内）零开销直调。
"""
from __future__ import annotations

import faulthandler as _faulthandler

try:  # unicorn 延迟导入：纯模块必须在没有 unicorn 的环境下也能 import
    import unicorn as _uc
    import unicorn.arm64_const as _arm64_const
    import unicorn.arm_const as _arm_const
    import unicorn.x86_const as _x86_const
except Exception:  # ImportError 或动态库加载失败
    _uc = None
    _arm64_const = None
    _arm_const = None
    _x86_const = None

__all__ = ["run", "available", "ARCHES", "ABI_PRESETS"]


# 架构表：名称 -> (UC_ARCH, UC_MODE)，全部小端。unicorn 不可用时为空 dict。
if _uc is not None:
    ARCHES = {
        "arm64": (_uc.UC_ARCH_ARM64, _uc.UC_MODE_ARM),
        "arm": (_uc.UC_ARCH_ARM, _uc.UC_MODE_ARM),
        "x64": (_uc.UC_ARCH_X86, _uc.UC_MODE_64),
        "x86": (_uc.UC_ARCH_X86, _uc.UC_MODE_32),
    }
else:
    ARCHES = {}

# ABI 预设：名称 -> 参数/返回/链接寄存器约定（纯数据，不依赖 unicorn）。
# lr_reg 为 None 表示该 ABI 无链接寄存器（返回地址在栈上，x86/x64）。
ABI_PRESETS = {
    "aapcs64": {
        "arch": "arm64",
        "arg_regs": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
        "ret_reg": "x0",
        "lr_reg": "x30",
        "sp_reg": "sp",
        "stack_args": False,
    },
    "aapcs32": {
        "arch": "arm",
        "arg_regs": ["r0", "r1", "r2", "r3"],
        "ret_reg": "r0",
        "lr_reg": "r14",
        "sp_reg": "r13",
        "stack_args": False,
    },
    "sysv64": {
        "arch": "x64",
        "arg_regs": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
        "ret_reg": "rax",
        "lr_reg": None,
        "sp_reg": "rsp",
        "stack_args": False,
    },
    "win64": {
        "arch": "x64",
        "arg_regs": ["rcx", "rdx", "r8", "r9"],
        "ret_reg": "rax",
        "lr_reg": None,
        "sp_reg": "rsp",
        "stack_args": False,
    },
    "cdecl": {
        "arch": "x86",
        "arg_regs": [],
        "ret_reg": "eax",
        "lr_reg": None,
        "sp_reg": "esp",
        "stack_args": True,  # 参数右到左压栈
    },
}

# 各架构默认 ABI（svc_policy="ret0" 时决定清零哪个返回寄存器）。
_DEFAULT_ABI = {"arm64": "aapcs64", "arm": "aapcs32", "x64": "sysv64", "x86": "cdecl"}

_CONST_MODULE = {
    "arm64": _arm64_const,
    "arm": _arm_const,
    "x64": _x86_const,
    "x86": _x86_const,
}
_REG_PREFIX = {
    "arm64": "UC_ARM64_REG_",
    "arm": "UC_ARM_REG_",
    "x64": "UC_X86_REG_",
    "x86": "UC_X86_REG_",
}
_PC_NAME = {"arm64": "PC", "arm": "PC", "x64": "RIP", "x86": "EIP"}
_SP_NAME = {"arm64": "SP", "arm": "R13", "x64": "RSP", "x86": "ESP"}
_PTR_SIZE = {"arm64": 8, "arm": 4, "x64": 8, "x86": 4}

# regs_out=None 时各架构默认快照的寄存器集。
_DEFAULT_REGS_OUT = {
    "arm64": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "sp", "pc", "x30"],
    "arm": ["r0", "r1", "r2", "r3", "r4", "r13", "r14", "r15"],
    "x64": ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rip"],
    "x86": ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "eip"],
}

_PAGE = 0x1000
_SVC_LOG_CAP = 64
_DIRTY_REGION_CAP = 512
_SENTINEL_PROBE = 0xD0000000

if _uc is not None:
    _ACCESS_KIND = {
        _uc.UC_MEM_READ: "read",
        _uc.UC_MEM_READ_UNMAPPED: "read",
        _uc.UC_MEM_READ_PROT: "read",
        _uc.UC_MEM_WRITE: "write",
        _uc.UC_MEM_WRITE_UNMAPPED: "write",
        _uc.UC_MEM_WRITE_PROT: "write",
        _uc.UC_MEM_FETCH: "fetch",
        _uc.UC_MEM_FETCH_UNMAPPED: "fetch",
        _uc.UC_MEM_FETCH_PROT: "fetch",
    }
else:
    _ACCESS_KIND = {}


def available() -> bool:
    """报告 unicorn 是否可导入（可用）。"""
    return _uc is not None


def _hex(value: int) -> str:
    """对外地址格式，与仓库 hex_addr 一致（本模块零依赖，不 import 仓库 utils）。"""
    return "0x%X" % int(value)


def _to_int(value) -> int:
    """宽松接受 int / 数值字符串（含 0x 前缀）。"""
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def _reg_id(arch: str, name: str):
    """按架构把寄存器名（小写，如 "x0"/"rdi"/"w0"）解析为 unicorn 常量。

    无法解析时返回 None（由调用方记入 warnings）。arm64 的 w0..w30 在
    unicorn 中有独立 W 寄存器常量，名前大写化后直接命中，无需特判。
    """
    module = _CONST_MODULE.get(arch)
    if module is None:
        return None
    return getattr(module, _REG_PREFIX[arch] + str(name).strip().upper(), None)


def _track_mapped(ranges: list[list[int]], start: int, end: int) -> None:
    """把 [start, end) 并入有序区间表（合并相邻/重叠）。"""
    ranges.append([start, end])
    ranges.sort()
    merged = [ranges[0]]
    for s, e in ranges[1:]:
        if s <= merged[-1][1]:
            if e > merged[-1][1]:
                merged[-1][1] = e
        else:
            merged.append([s, e])
    ranges[:] = merged


def _range_overlaps(ranges: list[list[int]], start: int, end: int) -> bool:
    """[start, end) 是否与区间表中任何区间相交。"""
    return any(s < end and e > start for s, e in ranges)


def _mem_map(uc, start: int, size: int, perms: int) -> None:
    """uc.mem_map 的 faulthandler 屏蔽包装（屏蔽窗口仅这一次 ctypes 调用）。

    见模块 docstring：unicorn 2.1.4 (Windows) 每个 Uc 实例的首次 mem_map
    会触发一次良性 first-chance access violation。宿主未启用 faulthandler
    时（如 IDA 内，faulthandler 默认关闭）零开销直调。
    """
    if _faulthandler.is_enabled():
        _faulthandler.disable()
        try:
            uc.mem_map(start, size, perms)
        finally:
            _faulthandler.enable()
    else:
        uc.mem_map(start, size, perms)


def _map_gaps(uc, ranges: list[list[int]], start: int, size: int, perms: int) -> None:
    """把 [start, start+size) 页对齐后，仅映射其中尚未映射的空隙并登记。

    image 区域允许重叠：重叠部分自然合并为一份映射（先映射者保留），
    避免 unicorn 对重复 mem_map 报 UC_ERR_MAP。ranges 为调用方维护的
    已映射区间表（不用 uc.mem_regions()：unicorn 2.1.4 的该 API 在
    Windows/Python3.14 下会触发 access violation，见模块 docstring）。
    """
    if size <= 0:
        return
    a = start & ~(_PAGE - 1)
    b = (start + size + _PAGE - 1) & ~(_PAGE - 1)
    cur = a
    for cs, ce in sorted(ranges):  # sorted() 快照：循环内 _track_mapped 改表安全
        if ce <= cur:
            continue
        if cs >= b:
            break
        if cs > cur:
            _mem_map(uc, cur, cs - cur, perms)
            _track_mapped(ranges, cur, cs)
        cur = ce
        if cur >= b:
            break
    if cur < b:
        _mem_map(uc, cur, b - cur, perms)
        _track_mapped(ranges, cur, b)


def run(
    image: dict[int, bytes],
    arch: str,
    entry: int,
    *,
    stop_at: list[int] | tuple = (),
    regs: dict[str, int] | None = None,
    writes: list[tuple[int, bytes]] | list[dict] = (),
    stack_size: int = 0x100000,
    max_instructions: int = 200000,
    svc_policy: str = "ret0",
    watch_writes: bool = True,
    readback_dirty: bool = True,
    readback_cap: int = 1 << 24,
    lr_sentinel: bool = False,
    stack_args: list[int] | tuple = (),
    reads: list[tuple[int, int]] | tuple = (),
    regs_out: list[str] | None = None,
) -> dict:
    """在 unicorn 中模拟执行一小段代码，返回结构化结果（键见模块/调用契约）。

    参数：
        image: {基址: 内容}，基址无需页对齐；重叠区域内容以先出现者为准，
            映射空隙补 0（mem_map 天然清零）。
        arch: "arm64" | "arm" | "x64" | "x86"。
        entry: 入口地址（arm 仅支持 ARM 模式，不处理 Thumb 位）。
        stop_at: 命中这些 PC 即停（该指令不执行），stop_reason="stop_at"。
        regs: 初始寄存器 {名字(小写): 值}；无法解析的名字收进 warnings。
        writes: 额外内存写入，元素为 (addr, data) 或 {"addr":.., "data":..}；
            目标页未映射时自动按 RW 补映射。
        stack_size: 栈尺寸（页对齐上取整），栈放在 image 最高端之上。
        max_instructions: 指令预算。计数为近似值：每条钩子回调按
            max(1, size//4) 累计（arm64/arm 恒为 1；x86 变长指令为近似）。
        svc_policy: "ret0" 记录系统调用并把 ABI 返回寄存器置 0 继续；
            "trap" 遇到即停（stop_reason="svc_trap"）。
        watch_writes: 是否用 UC_HOOK_MEM_WRITE 记录脏页。
        readback_dirty: 结束后是否回读脏页区间内容到 readbacks。
        readback_cap: 单个脏区间回读字节上限（超出截断读）。
        lr_sentinel: True 时布置返回哨兵页（arm64/arm 写入 lr 寄存器，
            x64/x86 按位宽压栈），PC 到达哨兵即停，stop_reason="sentinel"。
        stack_args: 栈传参数（cdecl 类 ABI），按列表顺序对应 arg0..argN，
            入栈时右到左压栈（arg0 在低地址），在哨兵返回地址之前布置，
            最终栈布局 [sp]=retaddr, [sp+width]=arg0, ...。
        reads: 结束后无条件回读的 (addr, size) 列表（结果并入 readbacks；
            与脏页回读互补——未被写过但仍需查看的缓冲区走这里）。
        regs_out: 结束时快照的寄存器名列表；None 用各架构默认集。

    返回 dict 的 ok/stop_reason 约定：
        ok=True  对应正常受控停止：stop_at / sentinel / budget / svc_trap；
        ok=False 对应 mem_fault / exception（以及一切前置校验失败，
        后者只返回 {"ok": False, "error": ...} 短形式）。
    """
    if not available():
        return {"ok": False, "error": "unicorn not installed: pip install unicorn"}
    if arch not in ARCHES:
        return {
            "ok": False,
            "error": "unsupported arch %r (expect one of: %s)"
            % (arch, ", ".join(sorted(ARCHES))),
        }
    if svc_policy not in ("ret0", "trap"):
        return {"ok": False, "error": "svc_policy must be 'ret0' or 'trap'"}
    try:
        entry = _to_int(entry)
        max_instructions = max(0, _to_int(max_instructions))
        readback_cap = max(0, _to_int(readback_cap))
    except (TypeError, ValueError) as exc:
        return {"ok": False, "error": "bad numeric argument: %s" % exc}

    warnings: list[str] = []
    uc = _uc.Uc(*ARCHES[arch])
    pc_id = _reg_id(arch, _PC_NAME[arch])
    sp_id = _reg_id(arch, _SP_NAME[arch])
    abi = ABI_PRESETS[_DEFAULT_ABI[arch]]
    ret_id = _reg_id(arch, abi["ret_reg"])
    mapped: list[list[int]] = []  # 已映射区间表（代替 mem_regions，见 _map_gaps）

    try:
        # ---- 1. 映射 image（重叠合并、空缺补 0），内容先出现者优先 ----
        regions = [(_to_int(base), bytes(content)) for base, content in image.items()]
        max_end = 0
        for base, content in regions:
            if content:
                _map_gaps(uc, mapped, base, len(content), _uc.UC_PROT_ALL)
            max_end = max(max_end, base + len(content))
        # 反序写入：后来者先写，先出现者最后写，重叠段以先出现者为准
        for base, content in reversed(regions):
            if content:
                uc.mem_write(base, content)

        # ---- 2. 额外 writes（未映射目标页按 RW 补映射）----
        for item in writes or ():
            try:
                if isinstance(item, dict):
                    waddr, wdata = item.get("addr"), item.get("data")
                else:
                    waddr, wdata = item[0], item[1]
                waddr = _to_int(waddr)
                wdata = bytes(wdata)
                if not wdata:
                    continue
                _map_gaps(uc, mapped, waddr, len(wdata), _uc.UC_PROT_READ | _uc.UC_PROT_WRITE)
                uc.mem_write(waddr, wdata)
            except (TypeError, ValueError, IndexError, _uc.UcError) as exc:
                warnings.append("writes item %r failed: %s" % (item, exc))

        # ---- 3. 栈：image 最高端之上，冲突继续上移；RW 权限 ----
        stack_size_aligned = max(_PAGE, (_to_int(stack_size) + _PAGE - 1) & ~(_PAGE - 1))
        stack_base = ((max_end + 0xFFFF) & ~0xFFFF) + 0x10000
        while _range_overlaps(mapped, stack_base, stack_base + stack_size_aligned):
            stack_base += 0x10000
        _map_gaps(uc, mapped, stack_base, stack_size_aligned, _uc.UC_PROT_READ | _uc.UC_PROT_WRITE)
        stack_top = stack_base + stack_size_aligned
        uc.reg_write(sp_id, (stack_top - 0x100) & ~0xF)

        # ---- 4. 用户初始寄存器 ----
        for name, value in (regs or {}).items():
            rid = _reg_id(arch, name)
            if rid is None:
                warnings.append("cannot resolve reg %r for arch %s" % (name, arch))
                continue
            try:
                uc.reg_write(rid, _to_int(value))
            except (TypeError, ValueError, _uc.UcError) as exc:
                warnings.append("set reg %r failed: %s" % (name, exc))

        # ---- 4.5 栈传参数（cdecl 类 ABI）：右到左压栈，arg0 在低地址 ----
        if stack_args:
            width = _PTR_SIZE[arch]
            for value in reversed([_to_int(v) for v in stack_args]):
                sp = uc.reg_read(sp_id) - width
                uc.reg_write(sp_id, sp)
                uc.mem_write(sp, value.to_bytes(width, "little"))

        # ---- 5. 返回哨兵页 ----
        sentinel = 0
        if lr_sentinel:
            cand = _SENTINEL_PROBE
            while _range_overlaps(mapped, cand, cand + _PAGE):
                cand += 0x10000
            # 代码钩子触发需要取指权限，哨兵页必须可执行
            _map_gaps(uc, mapped, cand, _PAGE, _uc.UC_PROT_ALL)
            sentinel = cand
            if arch in ("arm64", "arm"):
                uc.reg_write(_reg_id(arch, abi["lr_reg"]), sentinel)
            else:
                width = _PTR_SIZE[arch]
                sp = uc.reg_read(sp_id) - width
                uc.reg_write(sp_id, sp)
                uc.mem_write(sp, sentinel.to_bytes(width, "little"))
    except _uc.UcError as exc:
        return {"ok": False, "error": "setup failed: %s" % exc}

    stop_set = set()
    for addr in stop_at or ():
        try:
            stop_set.add(_to_int(addr))
        except (TypeError, ValueError):
            warnings.append("bad stop_at address %r ignored" % (addr,))

    state = {"count": 0, "reason": None, "fault": None, "error": None}
    svc_log: list[dict] = []
    dirty_pages: set[int] = set()

    def _read_pc() -> int:
        return uc.reg_read(pc_id)

    def _log_svc(pc: int, number: int) -> None:
        if len(svc_log) < _SVC_LOG_CAP:
            svc_log.append({"pc": _hex(pc), "number": int(number)})
        elif not any("svc_log truncated" in w for w in warnings):
            warnings.append("svc_log truncated at %d entries" % _SVC_LOG_CAP)

    def _hook_code(uc_, address, size, user):
        # 单步循环中每条指令触发一次：只记录本条指令的近似权重。
        # 停止判定在执行循环内做 —— 实测 unicorn 2.1.x 在代码钩子里
        # emu_stop() 无法阻止当前指令的副作用生效（见模块 docstring）。
        state["step"] = max(1, size // 4)

    def _hook_mem_write(uc_, access, address, size, value, user):
        page = address & ~(_PAGE - 1)
        last = (address + size - 1) & ~(_PAGE - 1)
        while page <= last:
            dirty_pages.add(page)
            page += _PAGE

    def _hook_mem_invalid(uc_, access, address, size, value, user):
        state["fault"] = {
            "type": _ACCESS_KIND.get(access, str(access)),
            "addr": _hex(address),
            "pc": _hex(_read_pc()),
        }
        return False  # 不自动映射：emu_start 抛 UcError，外层归因为 mem_fault

    def _hook_intr(uc_, intno, user):
        pc = _read_pc()
        if arch in ("arm64", "arm"):
            # unicorn 2.1.x：钩子里 PC 已是 SVC 的下一条指令，返回后直接继续。
            svc_pc, number = pc - 4, -1
            try:
                prev = int.from_bytes(uc_.mem_read(pc - 4, 4), "little")
                if arch == "arm64" and (prev & 0xFFE0001F) == 0xD4000001:
                    number = (prev >> 5) & 0xFFFF
                elif arch == "arm" and (prev & 0x0F000000) == 0x0F000000:
                    number = prev & 0x00FFFFFF
            except _uc.UcError:
                pass
            if number < 0:
                # UC_HOOK_INTR 对任何 CPU 异常都会触发（如未定义指令），
                # 并非都是 SVC；如实停止，避免 ret0 重试原地烧光指令预算。
                state["reason"] = "exception"
                state["error"] = "CPU exception (intno=%d) at pc=%s" % (intno, _hex(pc))
                uc_.emu_stop()
                return
            _log_svc(svc_pc, number)
        else:
            _log_svc(pc, intno)  # x86：INT 等入口落到此，intno 即中断向量号
        if svc_policy == "trap":
            state["reason"] = "svc_trap"
            uc_.emu_stop()
            return
        uc_.reg_write(ret_id, 0)

    def _hook_syscall(uc_, user):
        # unicorn 2.1.x：钩子返回后自动越过 SYSCALL（2 字节），勿手动 RIP+=2。
        _log_svc(_read_pc(), uc_.reg_read(ret_id))  # syscall 号在 rax/eax
        if svc_policy == "trap":
            state["reason"] = "svc_trap"
            uc_.emu_stop()
            return
        uc_.reg_write(ret_id, 0)

    uc.hook_add(_uc.UC_HOOK_CODE, _hook_code)
    if watch_writes:
        uc.hook_add(_uc.UC_HOOK_MEM_WRITE, _hook_mem_write)
    uc.hook_add(_uc.UC_HOOK_MEM_INVALID, _hook_mem_invalid)
    if arch in ("arm64", "arm"):
        uc.hook_add(_uc.UC_HOOK_INTR, _hook_intr)
    else:
        uc.hook_add(
            _uc.UC_HOOK_INSN, _hook_syscall, None, 1, 0, _x86_const.UC_X86_INS_SYSCALL
        )
        if arch == "x86":
            # SYSENTER/INT 等其余系统调用入口落到 INTR 钩子（仅记录/按策略处理）
            uc.hook_add(_uc.UC_HOOK_INTR, _hook_intr)

    # ---- 6. 单步执行循环 ----
    # 连续 emu_start + 钩子 emu_stop 无法阻止命中指令执行（见模块 docstring），
    # 故以 emu_start(pc, 0, count=1) 单步驱动，停止判定在步进前完成；
    # state["step"] 由代码钩子按 max(1, size//4) 近似赋值。
    pc = entry
    reason = None
    while True:
        if sentinel and pc == sentinel:
            reason = "sentinel"
            break
        if pc in stop_set:
            reason = "stop_at"
            break
        if state["count"] >= max_instructions:
            reason = "budget"
            break
        state["step"] = 1
        try:
            uc.emu_start(pc, 0, count=1)
        except _uc.UcError as exc:
            if state["fault"] is not None:
                reason = "mem_fault"
            else:
                reason = "exception"
                state["error"] = "UcError: %s" % exc
            break
        except Exception as exc:  # 模拟器异常一律结构化返回，不抛给调用方
            reason = "exception"
            state["error"] = "%s: %s" % (type(exc).__name__, exc)
            break
        state["count"] += state["step"]
        if state["reason"] is not None:  # svc_trap 等钩子内 emu_stop
            reason = state["reason"]
            break
        pc = _read_pc()

    # ---- 7. 脏页合并与回读 ----
    intervals: list[tuple[int, int]] = []
    if watch_writes and dirty_pages:
        pages = sorted(dirty_pages)
        start = prev = pages[0]
        for page in pages[1:]:
            if page == prev + _PAGE:
                prev = page
                continue
            intervals.append((start, prev + _PAGE))
            start = prev = page
        intervals.append((start, prev + _PAGE))
        if len(intervals) > _DIRTY_REGION_CAP:
            intervals = intervals[:_DIRTY_REGION_CAP]
            warnings.append("dirty intervals truncated at %d" % _DIRTY_REGION_CAP)

    readbacks: list[dict] = []
    if readback_dirty:
        for a, b in intervals:
            size = min(b - a, readback_cap)
            if size <= 0:
                continue
            try:
                data = bytes(uc.mem_read(a, size))
            except _uc.UcError as exc:
                warnings.append("readback at %s failed: %s" % (_hex(a), exc))
                continue
            readbacks.append({"addr": _hex(a), "size": size, "data": data})

    # ---- 7.5 显式 reads（未被写过但仍需查看的区域，如 emu_call 的输出缓冲）----
    for item in reads or ():
        try:
            raddr, rsize = _to_int(item[0]), min(_to_int(item[1]), readback_cap)
            if rsize <= 0:
                continue
            readbacks.append({"addr": _hex(raddr), "size": rsize,
                              "data": bytes(uc.mem_read(raddr, rsize))})
        except (TypeError, ValueError, IndexError, _uc.UcError) as exc:
            warnings.append("reads item %r failed: %s" % (item, exc))

    # ---- 8. 寄存器快照 ----
    out_names = list(regs_out) if regs_out is not None else list(_DEFAULT_REGS_OUT[arch])
    regs_dict: dict[str, str] = {}
    for name in out_names:
        rid = _reg_id(arch, name)
        if rid is None:
            warnings.append("cannot resolve reg %r for arch %s" % (name, arch))
            continue
        try:
            regs_dict[str(name).lower()] = _hex(uc.reg_read(rid))
        except _uc.UcError as exc:
            warnings.append("read reg %r failed: %s" % (name, exc))

    return {
        "ok": reason in ("stop_at", "sentinel", "budget", "svc_trap"),
        "stop_reason": reason,
        "arch": arch,
        "entry": _hex(entry),
        "pc": _hex(pc),  # 循环跟踪的 PC：停止点/故障指令本身，比寄存器残值更明确
        "instructions": state["count"],
        "regs": regs_dict,
        "stack": {"base": _hex(stack_base), "top": _hex(stack_top)},
        "svc_log": svc_log,
        "dirty": [{"addr": _hex(a), "size": b - a} for a, b in intervals],
        "readbacks": readbacks,
        "fault": state["fault"],
        "error": state["error"],
        "warnings": warnings,
    }
