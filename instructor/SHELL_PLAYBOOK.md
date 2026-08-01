# 商业壳分析作战手册（LLM Playbook）· 架构/格式/算法通用

> 用途：你是逆向分析助手，面对一个被商业壳加固的样本（Android ELF / Windows PE / iOS Mach-O）。
> 本手册是方法论的唯一权威来源：先做什么、用什么工具、什么时候升级手段。
> 速查卡可通过 MCP resource `ida://shell/playbook` 获取。
> 核心信条：**模拟执行优先，手写翻译是最后手段；数据比代码诚实；先定位算法族，再决定策略。**

---

## 速查卡（决策树，子代理只需这段）

1. `triage_shell()` 开局 → 看 traits 清单，确认是不是壳、什么流派
2. `scan_regions()` → DATA 段高熵区 = payload 候选；`find_embedded_files()` = 已能见的内嵌文件
3. `find_algo_signatures()` + `scan_immediates()` → 三层指纹定位解压/解密函数
4. `emu_call(解压函数, args=[...])` → **模拟执行 dump，禁止手写翻译**（2 小时上限铁律）
5. 看 write-watch 报告：写入区出现 ELF/PE/DEX 魔数 = 明文到手
6. `extract_layer(addr, size)` → `open_in_ida` 开新实例，**立刻并行分析下一层**
7. 模拟跑不动 → 按升级阶梯走（见 §5），不要直接跳到手写
8. 运行时 dump 到手 → `analyze_dump(file, base)` 一条龙载入；IDA 未分析区读不动
   → disasm_text 自动 capstone 兜底，要真 IDB 代码先 `force_code_range`（见 §8）

---

## §1 通用工作流（七步）

| 步骤 | 工具 | 产出 |
|---|---|---|
| 1 三角测量 | `triage_shell` | 格式/段/权限/字符串/syscall 密度 → 壳特征清单 |
| 2 找 payload | `scan_regions` | 高熵 blob 地址（无需任何格式知识） |
| 3 定位算法 | `find_algo_signatures` / `scan_immediates` | 候选解压/解密函数地址（referenced_by） |
| 4 读代码定性 | `compress_function` / `disasm_text` | 确认算法族（混淆代码上 decompile 会误导，信任反汇编层） |
| 5 模拟执行 | `emu_call` / `emu_run` | 解压后明文 + write-watch 报告 |
| 6 落地验证 | `dump_region` / 魔数校验 | 文件落盘 %TEMP%/ida_mcp_out/ |
| 7 下一层 | `extract_layer` → `open_in_ida` | 新实例并行，层间不互相等 |

拿到**任何一层**明文就开新实例。不要试图一次解到底。

## §2 三层算法指纹（魔改算法的对策）

标准字节签名**扫不到魔改算法**（上次魔改 LZMA 就是教训）。必须分层：

- **第 1 层 已知常量**（`find_algo_signatures` → constants）：AES S-box/Te/Td、SM4 S-box、
  ChaCha "expand 32-byte k"、SHA-2 K 表、MD5 K 表、CRC32 表、Base64 字母表、xxhash 质数。
  只抓标准件。命中 → referenced_by 给出使用它的函数。
- **第 2 层 统计表检测**（同工具 → permutation_tables）：256 字节全排列 = S-box/RC4 候选。
  **自定义表也跑不掉**，与算法族无关。
- **第 3 层 立即数习惯**（`scan_immediates`）：函数级常量画像。
  range coder 指纹：`0x1000000`(kTopValue) / `0x800`(kBitModelTotal=1<<11) / `1024`(初始化=kBitModelTotal/2)
  / `1846`/`768`(概率表步长) / `0xFFFF0000`；TEA delta `0x9E3779B9`；ChaCha 四个 sigma dword；
  SHA-256/MD5 初始链值；CRC32 多项式 `0xEDB88320`；SM4 FK。
  加上"高 popcount 异常常量"排行——**任何自定义算法都会埋常量**。
  魔改 LZMA 的辨认点：骨架是 range coder（概率表+归一化循环+>>11），改的只是寄存器宽度/
  属性解析/表布局——骨架在第 3 层照样现形。

## §3 壳特征速查（triage 的 traits 对照）

| 特征 | ELF/Android | PE/Windows | 含义 |
|---|---|---|---|
| 节头/节区异常 | e_shnum=0（无节头） | .vmp/.themida/.enigma 节名 | 加固痕迹，确认是壳 |
| 权限 | RWX 段 | 可写+可执行节 | 解压器存在，往这儿写代码 |
| 体积比 | 小 .text + 大 DATA/BSS | 小代码节 + 大数据节 | payload 藏在数据里 → scan_regions |
| 符号 | ET_DYN 且无导出 | 导出表为空/诡异 | 加固 |
| 自加载 | /proc/self/exe、linker、dlopen | LoadLibrary+GetProcAddress 动态解析 | stub 自己映射 |
| 监控 | SVC 蹦床（函数≥3个 syscall） | int 2e/sysenter 直调、反调试 API | syscall 级监控/反调试 → 别上调试器 |
| 反调试字符串 | ptrace/TracerPid/frida/magisk | IsDebuggerPresent 等 | 优先 Unicorn 模拟 |

## §4 模拟执行纪律（emu_call / emu_run）

- **ABI**：arm64→aapcs64(x0-x7)、arm→aapcs32(r0-r3)、x64 ELF→sysv64(rdi,rsi,rdx,rcx,r8,r9)、
  x64 PE→win64(rcx,rdx,r8,r9)、x86→cdecl。`abi="auto"` 按 IDB 推断；参数不够加 `regs={}` 覆盖。
- **指针参数**：args 里写 `"@in"`/`"@out"` 指代模拟缓冲区；输入用 `in_addr`+`in_size` 从 IDB 复制。
- **结果看三样**：`stop_reason`（sentinel=正常返回）、`regs`（x0/rax=返回值常是新长度）、
  write-watch（dirty 区 + 魔数扫描——**明文落在哪直接告诉你**）。
- **mem_fault 排查**：fault.addr 接近某段 → 用 `writes` 手工补页；是 NULL+小偏移 → 结构体指针参数没设全。
- **svc_trap/svc_log**：壳在模拟里发 syscall → 默认 ret0 放行；依赖返回值真实的（如文件读）→ 换真机或手工喂。
- **预算**：默认 200 万指令；解压大 payload 上调；budget 停了先看已完成进度，别直接加 10 倍。
- **手写翻译铁律**：任何手写解压器/解密器投入超过 2 小时必须停下来回到模拟路线。
  模拟路线全灭才允许手写，且以输入输出对逐字节验证（oracle 思路）。
- **适用边界**：JIT/翻译缓存块依赖活动进程的 rbp/rsp 帧上下文与宿主预置寄存器，
  emu_run/emu_call 从干净 CPU 上下文起步，跑不出真实行为——此类块走静态路线
  （`scan_blocks`/`disasm_text`/`force_code_range`），或显式传 `regs` 补上下文。

## §5 升级阶梯（模拟跑不动时，逐级升，别跳级）

1. **Unicorn 全映像模拟**（emu_run/emu_call，默认）——80% 的壳死在这层
2. **Unicorn + 手工补环境**：补页、喂假 syscall 返回、patch 掉反模拟指令（emu_run writes/regs）
3. **QEMU user-mode + gdb**：需要真实 syscall 语义时；断点 dump 内存
4. **IDA 调试器/Frida 真机**：有反调试时先 patch 反调试（patch_bytes），hook memcpy/memset 看写入模式
5. **静态裂缝**：错误处理路径喂错输入逼它吐明文；内存 dump 里搜 7fELF/dex\n/MZ
6. **抠代码改写**：把解压函数机器码抠进独立 .so，dlopen 调用——比手写快 10 倍
7. **手写翻译**（终极手段）：用第 1-6 步攒下的输入输出对做逐字节 oracle 验证

## §6 与其他工具的协同

- **SEMZ**：批量扫读用 `compress_function`（配 `ida://semz/manual`）；小函数直接 `disasm_text`；
  混淆/虚拟化代码**不信 decompile**（伪 C 会把混淆块读成正常逻辑）。
- **find_bytes**：已知 block header 模式直接搜，别追寄存器（上次的 X28 教训：数据比代码诚实）。
- **多实例**：网关天然支持多 IDA 实例；每层明文一个实例，端口从 10000 递增。
- **落盘纪律**：%TEMP%/ida_mcp_out/ 的产物是临时的——任务结束先征得用户确认再删除。

## §7 禁忌清单

- ❌ 逐行精读 ultra 压缩输出（宏要心算，错误率高于省的 token）
- ❌ 追寄存器传播链超过两层（去搜数据模式）
- ❌ 手写任何超过 2 小时的翻译器
- ❌ 在混淆代码上相信 decompile 输出
- ❌ 对着一个层死磕到底（拿到明文就开新实例并行）
- ❌ 手工 undefine+make_code 逐段重试未分析区（用 `force_code_range` 一次扫完）
- ❌ 对依赖活动帧上下文的 JIT 块用 emu_run/emu_call（走静态或显式 regs）

## §8 未分析区、运行时内存与 JIT/OLLVM（工具层）

- **未分析区反汇编兜底**：`disasm_text` 范围模式 / `linear_disasm` 在 IDA 未分析的
  数据区（seg_40 这类）自动回退 capstone 字节级解码（响应带 `fallback:"capstone"`）
  ——先拿到答案；需要变成真 IDB 代码（decompile/xref/emu 可用）再调
  `force_code_range(start, end)` 一次强制解码，替代手工 undefine+make_code 重试。
- **运行时内存载入**：壳分析 80% 是运行时内存。`load_memory_dump(file, base)` 把
  dump 载为临时段；`dump_process(pid, ranges)` 直接从活动进程抓（Windows
  ReadProcessMemory / Linux /proc/pid/mem）；`analyze_dump(file, base)` 一条龙：
  载入 → 入口启发（MZ/ELF magic，否则序言扫描）→ 强制解码 → capstone 预览。
  载入后全部常规工具（decompile/disasm/xrefs/emu_*）直接可用。
- **翻译缓存/JIT**：`scan_blocks(base, end)` 块入口扫描（序言签名+对齐启发）；
  `resolve_jump_slots` 编码跳转槽分类（suspicious=疑似待懒解析）；
  `find_refs_in_range(base, end, target_start, target_end)` 全缓存引用扫描=判定点发现。
- **diff**：`diff_regions(a, b)` 两个 dump/两段内存对比（源可为文件或 IDB 地址），
  层间/版本差异定位。
- **OLLVM**：`detect_ollvm(func)` 评分（cmov 密度/不透明谓词/平坦化信号，
  ≥60 likely_ollvm）；`ollvm_simplify(ea)` 保守 patch 可静态判定的不透明谓词
  （默认 `dry_run=true` 先看报告，宁漏勿错）。

## §9 编排与对抗核查（LLM 主导 80%，人审 20%）

**分工原则**：机械循环塌缩进插件一次调用跑完；LLM 审查裁决书与 review_flags；
人类（或对抗子代理）只负责最终判断幻觉。

1. `auto_unpack_layer(func?, entry?)` 一次调用完成：immediates 候选 → xref 调用点 →
   probe 跑到调用点抓全部 ABI 参数 → 分类（image_ptr 克隆 IDB / runtime_ptr 克隆 probe
   脏页 / null·wild_ptr 换零页 / scalar 直传）→ 修补被 svc 假值污染的指针 → 跑解压器 →
   输出**裁决书**：verdict / ret / reasons / **review_flags（每条启发式假设的清单）** / evidence。
2. LLM 的 20%：逐条审 review_flags——哪条假设错了结论会崩？最脆的那条手工验证
   （用 emu_call 显式参数重跑对照）。
3. **对抗核查**：裁决为 success 的产物必须过独立证伪——用 resource
   `ida://shell/verifier_prompt` 模板喂给一个干净上下文的子代理，只接受它亲自复算的
   证据（尺寸闭环、熵剖面、反格式化处理、边界完整性），判定 CONFIRMED 前不得向下游使用产物。
4. 幻觉防线是**机器证据**，不是措辞：sentinel 返回、ret==0、produced==expected、
   熵降、魔数/指令密度——五缺三就按 failed 处理。
5. 编排器 probe_failed / runtime_ptr_unresolved = 环境太假（svc ret0 不够用）：
   升级阶梯 §5 第 2 级（补环境/喂真 syscall），不要硬猜参数。
