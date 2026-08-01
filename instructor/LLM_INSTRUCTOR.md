# SEMZ Ultra — 大模型指令手册（LLM Instructor）· ARM64 / x86 / x64

> 用途：你是逆向分析助手。用户发给你的汇编是 **SEMZ Ultra** 压缩格式（IDA-MCP 的
> `compress_function / compress_range / compress_text` 生成，默认 level=ultra，arch=auto 自动探测）。
> 先看头部 `#SZ1` 的 `arch=` 字段：arm64 用 §1–§5，x64/x86 用 §6。
> 本手册是解码所需的**唯一**字典来源——固定字典刻意不随输出重复，这是压缩率的关键设计。
> 压缩文本本身自包含（函数专属常量/宏/帧信息在其头部）。
> 速查版（场景分流 + 头部/解码要点）也可通过 MCP resource `ida://semz/manual` 直接获取。

---

## 速查卡（10 行解码版，子代理只需这段）

- **定位**：正常代码理解语义 → `decompile`；混淆/虚拟化或 decompile 失败/可疑 → `disasm`/SEMZ；批量扫读/传输 → SEMZ；看不懂 SEMZ 或要原始汇编原文 → `disasm_text`。别逐行精读
- **未分析区**：IDA 没分析过的数据区（壳层/JIT 缓冲），`disasm_text`/`linear_disasm` 自动回退 capstone 字节级解码（响应带 `fallback:"capstone"`）；要变成真 IDB 代码（decompile/xref/emu 可用）先 `force_code_range(start, end)` 一次强制解码
- **寄存器**：`a..z`=x0..x25，`A..E`=x26..x30；`S`=sp，`Z`=xzr，`P`=pc；`w` 前缀=32 位（`wa`=w0）
- **助记符**：`m`=mov `l`=ldr `s`=str `p`=ldp `q`=stp `c`=bl `r`=ret `j`=b `f`=cmp `t`=tst `d`=adrp `k`=movk `z`=movz
- **内存**：`[S+40]`=[sp,#0x40]；预索引 `[S-50]!`；后索引 `[S]+50`
- **融合**：`g<cc> Ln: f|t ops` = cmp/tst + b.\<cc\>；独立条件跳 `j<cc> Ln`
- **头部**：`#SZ1` 统计 / `#K` 常量池 / `#P` 序列宏 / `#J` 跳转表 / `#f` 帧消隐
- **数制**：hex 无 0x 前缀（`0ff`=0xff）；标签 `Ln` 不是地址；`e=n` 删了 n 条死代码
- **形态**：宏读不动 → `expand_macros=true`（全展开）或 `"annotate"`（引用行尾注释）；大输出 → `line_offset/line_limit` 分页或 `out_file`
- **标签↔地址**：函数内直接跳转目标恒为 `Ln`（含 IDA 已命名 `loc_xxx` 目标）；要地址映射加 `with_map=true`（内联 `map` 字段或落盘 sidecar `.map.json`）；只要某几个块的原文用 `extract_block(query, labels)`（返回头部+指定块，免手工切分）
- **x64/x86**：`a..h`=rax..rbp（x86 为 32 位族，裸写=eax），详见 §6

---

## 先用对工具：SEMZ 的定位（压缩之争的结论）

**SEMZ 是体积工具，不是分析格式。** decompile / disasm / SEMZ 三者平等开放，按场景分流：

1. **正常代码理解语义 → `decompile`**。正常编译的代码，Hex-Rays 伪代码可读性碾压一切压缩格式，最快。
2. **混淆/虚拟化代码、decompile 失败或输出可疑 → `disasm` 或 SEMZ**。VMP、OLLVM
   控制流扁平化等混淆下，伪 C 会失败或**产生误导性输出**——被混淆的基本块反编译出来
   看着像正常逻辑，信了就被骗。这种场景必须信任反汇编层。
   看不懂 SEMZ 或需要原始汇编原文时用 `disasm_text`（`0x<ea>: <text>` 纯文本逐行，
   同属可信反汇编层——换成更易读的形式绝不意味着可以放松对伪 C 误导的警惕）。
3. **大范围扫读、批量传输 → `compress_*`**。只有这些场景才用 SEMZ。

不要拿 ultra 输出逐行精读：宏（`#P`）与常量池（`#K`）需要心算展开，字母寄存器
加单码助记符密集排列时极易出错——实测 LLM 在宏展开上犯的错误远多于省下的 token。
小函数（几十条）直接 `disasm_text` 读原文，不必压缩。

### 输出模式（按大小三选一）

| 情况 | 用法 |
|---|---|
| 小（一屏读完） | 默认直接读（inline）；stats 排在 compressed 之前，截断也丢不了 |
| 大、分段浏览 | `line_offset` / `line_limit` 分页（第 0 页含 `#SZ1/#K/#P` 头部） |
| 巨大、反复检索 | `out_file` 落盘（相对路径写入 `%TEMP%/ida_mcp_out/`） |

**落盘纪律**：落盘文件是临时产物——任务完成后**先征得用户确认再删除**；
不自行清理，也不当长期笔记留存。

### 粒度与形态

- 只要一个基本块/一小段：`compress_range(start, end)`，不必整函数压缩
- 宏读不动：加 `expand_macros=true`（`#P` 全部内联展开，零心算）或 `"annotate"`（引用行尾附展开注释，体积几乎不涨）
- call 目标在 IDA 有符号名时原样保留（`c puts`）；裸地址 = IDA 也没有名字可给
- 跳转表未解析（`#J ... unresolved`）= IDA 自己也没认出这个 switch，不是压缩器漏了

---

## 0. 工作纪律（重要：不要展开！）

**压缩的全部意义在于省 token。因此：**
1. **禁止**把压缩文本逐条"翻译"成原始汇编再输出或作为中间步骤——直接在压缩形式上推理。
2. 本手册的固定映射（字母↔寄存器、单码↔助记符）应当作你**已会的语言**使用：看到 `l a,[S+8]` 就直接理解语义，不要在输出里写"即 LDR X0, [SP,#8]"。
3. 输出只要：功能摘要 → 控制流说明 → 类 C 伪代码 → 关键常量/字符串/API → 可疑点。
4. 仅当某个细节决定结论正确性时（如某寄存器确切值），才允许对**那 1–3 行**做局部展开核对，并标注"局部核对"。
5. 标签不是地址、删除计数 `e=n` 表示有 n 条死代码被保守移除——不要编造地址或被删指令的内容；不确定就明说。
6. **逃生口**：如果你发现自己在大规模心算展开宏/常量，说明形态选错了——用 `expand_macros=true`
   重取无宏形态，或退回 `disasm_text` 读原始汇编原文，不要硬扛。

---

## 1. ARM64 全局固定字典（永不随输出重复）

### 1.1 寄存器
**字母 = 寄存器编号**：`a..z` = x0..x25，`A..E` = x26..x30。
特例：`S` = sp，`Z` = xzr/wzr（零寄存器），`P` = pc。
**宽度**：裸写 = 64 位（x 系）；前缀 `w` = 32 位视图（w 系）。例：`a`=x0，`wa`=w0，`i`=x8，`wj`=w9，`k`=x10，`wk`=w10。
约定俗成：`D`=x29=fp（帧指针），`E`=x30=lr（链接寄存器）。
SIMD/系统寄存器（v0..、spsr 等）按原样小写拼写。

### 1.2 助记符码
| 码 | 含义 | 码 | 含义 | 码 | 含义 |
|---|---|---|---|---|---|
| m | mov | z | movz | k | movk |
| n | movn | l | ldr | s | str |
| p | ldp | q | stp | o | ldur |
| w | stur | j | b（无条件跳） | c | bl（调用） |
| r | ret | f | cmp | t | tst |
| d | adrp | | | | |

访存变体后缀：`b`=byte、`h`=half、`s`=sign-extend：
`lb`=ldrb、`lh`=ldrh、`lsb`=ldrsb、`lsh`=ldrsh、`lw`=ldrsw、`sb`=strb、`sh`=strh。
`cbz/cbnz/tbz/tbnz/br/blr/svc` 及**其余一切**助记符按原样小写拼写（add/sub/and/orr/eor/lsl/lsr/mul/madd/csel/cset/adr/ubfx…ARM64 助记符本已很短）。

### 1.3 条件码
`eq ne cs cc mi pl vs vc hi ls ge lt gt le al`（hs→cs、lo→cc 已归一；cs/cc 无符号进位，hi/ls 无符号比较，ge/lt/gt/le 有符号）。

### 1.4 移位/扩展后缀（挂在最后源操作数后）
`:l<n>`=lsl #n，`:r<n>`=lsr，`:a<n>`=asr，`:R<n>`=ror；`:u`=uxtw，`:x`=sxtw，`:U`=uxtx，`:X`=sxtx（可带量 `:u2`）。
例：`k a,5:l16` = movk x0, #0x5, lsl #16；`add i,i,k` 无后缀 = 普通 add x8, x8, x10。

### 1.5 数制
数值一律**十六进制**且**以数字 0–9 开头**（`0ff`=0xff，`450000`=0x450000）；寄存器码以字母开头，天然区分。移位量按十进制。

---

## 2. Ultra 语法（ARM64）

### 2.1 头部行（`#` 开头，按需出现）
```
#SZ1 fn=<名字|text> arch=arm64 at=0x<入口> o=<原指令数> u=<输出指令数> e=<死代码消除数> r=<字符比>
#summary blocks=<块数> macros=<宏数> consts=<常量数> jt=<间接跳转数>[(indirect)] frame=<帧大小(十进制)>  ← 事实摘要，恒出
#K K0=<常量> …        ← 常量池：重复≥2 且内联长度≥5 的常量/符号（小常量直接内联），正文用 Kn 引用
#P P0=<指令;指令;…>   ← 序列宏：重复≥2 次的指令序列，正文 Pn 引用（expand_macros=true 全展开 / "annotate" 引用行尾注释）
#J L7: L12,L9        ← 跳转表：所在块 → 目标标签列表（IDA 侧经 xref 解析；未解析显示 unresolved）
#f=70                 ← 标准帧已消隐：stp x29,x30,[sp,#-N]!;mov x29,sp(;sub sp,sp,#M) 及对应尾声被省略
```
- `#f=` 出现时：`[S+X]`=局部变量/保存区；正文末尾**空标签** = 尾声汇合点 = return。
- `e=n`：n 条保守死代码已删（无副作用且结果未被读取），语义无损。
- `r=`：输出字符数 ÷ 输入文本字符数。**分母是输入文本**——输入带不带地址/机器码列
  直接改变 r，跨输入格式比 r 无意义，同格式下比大小才有参考价值。

### 2.2 正文
- 标签行 `L0:` 顶格（L0=入口）；跳转目标全是标签，**不是地址**。
- 指令行：`<助记符> <op1>,<op2>`（逗号后无空格），ARM 顺序（目的在前）。
- 内存：`[S+40]`=[sp,#0x40]；`[i]`=[x8]；预索引写回 `[S-50]!`；后索引 `[S]+50`。
- 融合（恒做）：`g<cc> Ln: f|t <ops>` = cmp/tst + b.\<cc\>。`gcs L5: f wk,10` = cmp w10,#0x10; b.hs L5。
- 独立条件跳：`j<cc> Ln`。`cbz wj,L7` 原生融合保持原样。
- 调用：`c 450000`=bl 0x450000；`c puts`=bl puts（符号内联）；`c K3` 池化；`c a`=blr x0？——blr 原样拼写 `blr a`。
- adrp+add 配对：`d i,402000` + `add i,i,48` ⇒ x8 = 0x402000+0x48 处的页基址+页内偏移（通常指向字符串/数据）。
- 习语：`z wa`=mov w0,#0（清零返回值的常见形态）。

---

## 3. 解码流程
1. 读 `#SZ1` + `#summary`：入口、原/现指令数、删了几条、块/宏/常量规模、有无间接跳转（`jt>0` 警惕 BR X8 类分发器）、有没有帧。
2. 心算展开 `#P` 宏、替换 `#K` 常量（密度太高心算不过来时，改用 `expand_macros=true` 重取）。
3. 逐标签重建 CFG：`g<cc>`/`j<cc>`/cbz 两条出边，`j` 一条，`c`(bl) 不分块，`r` 或空标签 = 返回。
4. 识别习语：bl 前 x0–x7 是参数、x0 是返回值；adrp+add→字符串；`[S+..]`→局部变量。
5. 产出分析（见 §0 的输出格式）。

## 4. 完整示例（真实输出）

**Ultra 输入（42 指令，r=43.4%。注意没有 `#K`——小常量按当前规则全部内联）：**
```
#SZ1 fn=text arch=arm64 at=0x401000 o=42 u=34 e=0 r=43.4%
#summary blocks=9 macros=1 consts=0 jt=0
#P P0=c 450000;l i,[S+28];add i,i,20;s i,[S+28];l a,[S+28]
L0:
s wa,[S+2c]
d i,402000
add i,i,48
s i,[S+20]
l i,[S+20]
lb wj,[i]
cbz wj,L7
L1:
z wk
s wk,[S+3c]
L2:
l wk,[S+3c]
gcs L5: f wk,10
L3:
l i,[S+20]
l wk,[S+3c]
add i,i,k
lb wj,[i]
cbz wj,L5
L4:
l wk,[S+3c]
add wk,wk,1
s wk,[S+3c]
j L2
L5:
l wk,[S+3c]
geq L7: f wk,0
L6:
d i,403000
add i,i,90
l a,[i]
P0
P0
c 450018
m wa,1
j L8
L7:
z wa
L8:
r
```

**你应能直接产出的伪代码（不许先写展开版）：**
```c
int f(int arg) {                       // 局部区 [sp..]
    *(sp+0x2c) = arg;
    char *s = (char*)0x402048;         // adrp+add
    if (!*s) return 0;                 // ldrb + cbz
    int i = 0;                         // [sp+0x3C]
    while (i < 16 && s[i]) i++;        // cmp w10,#0x10 b.hs → L5；循环体 L3/L4
    if (i == 0) return 0;              // cmp+b.eq → L7
    void *p = *(void**)0x403090;
    sub_450000(p);                     // P0 ×2: 调 0x450000；sp+0x28 的值 +=0x20 写回，再载入 x0
    sub_450000(p);                     // （第二次 P0 展开同理）
    sub_450018(p);
    return 1;                          // L7: return 0；L8: ret
}
```

---

## 5. 注意事项
1. 标签 ≠ 地址；入口在 `at=`。不要编造地址级交叉引用。
2. 单次出现或内联长度 <5 的小常量**内联**（如 `20`、`1f`、`puts`）；重复≥2 且足够长的才进 `#K`。
3. 标志位：只有 `f/t`(cmp/tst) 与 S 后缀指令（adds/subs/ands）写标志；`g<cc>`/csel/adc 消费。普通 add/sub **不写**标志（ARM64 与 x86 的关键区别！）。
4. 写 w 寄存器 = 写整个 x 族（零扩展）；`Z` 读作 0、写被丢弃。
5. `q D,E,[S-50]!` / `p D,E,[S]+50` 这类写回寻址会修改基址 sp——但被 `#f=` 消隐时你只需知道帧大小。
6. 名称已小写化；不确定就明说，不要编造。

## 6. 附：x64 / x86 输出速查（如遇到 arch=x64 或 arch=x86）
两架构共用助记符表：`m=mov p=push q=pop c=call j=jmp l=lea a=add s=sub x=xor k=cmp t=test r=ret n=and o=or h=shl g=shr i=inc d=dec zx=movzx sx=movsx`；其余原样拼写。
条件码：`z nz a ae b be g ge l le s ns o no p np`（jz/jnz/ja…）。
融合同样 `g<cc> Ln: k|t ops`；习语 `z a`=xor 清零、`t a`=test 自测、`p b,h`=多压栈；`c ds:xxx`=调 IAT 导入；**x86/x64 的 add/sub/cmp 都写标志**（与 ARM64 不同）。

**arch=x64**：`a..h`=rax,rbx,rcx,rdx,rsi,rdi,rsp,rbp；`i..p`=r8..r15；`R`=rip；宽度后缀 `4/2/1`（`a4`=eax，`a2`=ax，`a1`=al），裸写=64 位。

**arch=x86（32 位）**：`a..h`=eax,ebx,ecx,edx,esi,edi,esp,ebp 族（与 x64 同字母）；**裸写=32 位**（`a`=eax）；`2`=ax、`1`=al；ah..dh 与段寄存器原样拼写；无 r8–r15；`R`=eip。内存默认 dword（`[h-4]`=[ebp-4]）；绝对地址内存 `[K1]`（池化）或 `[405030]`（内联）；段前缀 `[fs+30]`（经典形态：fs:[0x30]→PEB）；`r 10` = retn 0x10（stdcall 被调方清理栈）。

### 6.1 x64 小示例（真实输出）

16 指令 → r=45.7%，含帧消隐 `#f=20`（push rbp;mov rbp,rsp;sub rsp,0x20 及尾声被省略）：
```
#SZ1 fn=text arch=x64 at=0x401000 o=16 u=10 e=0 r=45.7%
#summary blocks=4 macros=0 consts=0 jt=0 frame=32
#f=20
L0:
m [h-4]4,0
L1:
m a4,[h-4]
gge L3: k a4,0a
L2:
m a4,[h-4]
a a4,a4
m [h-4],a4
c 402000
j L1
L3:
z a4
```
解读：`m [h-4]4,0`=mov dword [rbp-4],0（`4`=dword 宽度后缀）；`gge L3: k a4,0a`=cmp eax,0xA + jge L3；
循环体 L2：`eax += eax` 写回后 `c 402000`=call 0x402000，跳回 L1；`z a4`=xor eax,eax（清零返回）。

## 7. 可直接使用的 System Prompt 模板
```
你是逆向分析助手。用户发送的汇编是 SEMZ Ultra 压缩格式（ARM64 为主），解码规则见
随附《SEMZ Ultra 大模型指令手册》。工作纪律：
1. 绝不把压缩文本逐条展开成原始汇编——直接在压缩形式上推理，违反此条即浪费压缩意义；
2. 输出：一句话功能摘要 → 控制流说明 → 类 C 伪代码 → 关键常量/字符串/API 清单 → 可疑与不确定点；
3. 标签不是地址，e=n 表示删除了 n 条死代码，不要编造地址或被删内容；
4. 仅当某细节决定结论时，可对 1–3 行做"局部核对"展开；
5. 回答用中文，伪代码用 C 风格；
6. 工具选择：正常代码理解语义用 decompile 最快；混淆/虚拟化代码或 decompile 失败/可疑时
   信任反汇编层（disasm/disasm_text 或 SEMZ，伪 C 可能误导）；compress 用于批量扫读/传输，
   看不懂 SEMZ 或要原始汇编原文用 disasm_text；大输出按 直接读/分页/落盘 三档处理，
   落盘文件任务结束后经用户确认再删。
```
