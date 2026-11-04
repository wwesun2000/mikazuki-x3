# 从原机器码恢复的 ScriptData 小核心

最终状态（2026-10-30）：本页后文保留各批次历史。最终冻结构建已通过 readers 470、strings 56、history 809、tables 460、libc 292 和增强 MMI libc 248 原指令差分；原 MMI 失败记录仍保留。`10D868` 的普通选择转移已接入 `invoke_recovered` 与真实 ChoiceServices 路径，并有 33 组持久状态差分；这不代表低层 `invoke_script_data` 的所有特殊回调已开放。当前完整状态以 [NATIVE_CORE_PROGRESS.md](NATIVE_CORE_PROGRESS.md) 和 `analysis/native-core/final-verification-20261030.json` 为准，后文“仍待差分”等均对应当时批次。

实现为 `port/core/script_data.hpp`／`.cpp`，共享原字符串与复制代码在 `port/core/source_libc.hpp`／`.cpp`。统一接口：

```cpp
std::uint64_t kx3::invoke_script_data(
    GuestMemory&, std::uint32_t entry, std::uint32_t self,
    std::uint64_t a1, std::uint64_t a2, std::uint64_t a3 = 0);
```

GuestMemory 是主线程提供的32MiB、little-endian客体内存。原32位地址只用于该内存访问，不转换成宿主指针。

## 来源与范围

源 ELF `SLPM_664.52` SHA-256：

```
50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160
```

第一批证据为 `analysis/ghidra/scriptdata-readers-v1/`，Ghidra12.1.4、语言 `r5900:LE:32:default`。已逐条将20个函数导出的原字节与 ELF canonical file offset 比对，全部一致。最初16个闭合入口共532字节；按入口升序拼接 `LE32 entry + LE32 body_length + body_bytes` 的 SHA-256 为：

```
e4b38407681394bb0dd5ce3a96e45da0bb9a6ef4a01a5ec1d850479939e7c60d
```

`analysis/ghidra/reader-dependencies-v1/functions/001fdc64.json` 随后提供原strlen实现，使 `10D680` 成为第17个闭合入口。它不是凭函数名或旧模型替换成宿主strlen。

| 原入口 | 恢复行为 | 返回值定义 |
| --- | --- | --- |
| 10D5D8 | 从self+D8游标连续读a1字节，BE拼接，每字节写回游标 | 32位SLL结果符号扩展到64位 |
| 10D610 | D8游标加a1，再减当前block的base | signed32 offset的64位位型 |
| 10D638 | 读取一字节；若为0再跳两字节，最后查询offset | 尾调10D610的返回值 |
| 10D680 | 返回原D8指针，扫描NUL后将游标推进length+1 | 原LW指针位型，sign-extended |
| 10D6C8 | 对self+DC执行同样的BE读取 | 同10D5D8 |
| 10D700 | D8设为当前block base+a1 | 原v0未写 |
| 10D720 | 读D8字段 | LW sign-extended |
| 10D728 | D8复制到DC | 原v0未写 |
| 10D738 | a1低32位写D0 selector | 原v0未写 |
| 10D740 | 读D0 | LW sign-extended |
| 10D748 | 读D4字段 | LW sign-extended |
| 10D780 | a1低32位写D4 | 原v0未写 |
| 10D788 | DC游标加a1并返回当前base相对offset | signed32 offset的64位位型 |
| 10D7B0 | DC设为当前block base+a1 | 原v0未写 |
| 10D7D0 | selector=a1+0x20，然后D8设为选中base | 原v0未写 |
| 10D800 | selector=a1+0x2A，然后D8设为选中base | 原v0未写 |
| 10D830 | selector=a1，D8设为新base+a2 | 原v0未写 |

当前base的原寻址顺序为 `load32(load32(self+8+(load32(self+D0)<<2))+0x430)`。字段D4的更高层游戏意义不在本批推定。

## 第二批：历史位字段与标签表

`analysis/ghidra/scriptdata-all-v1/functions/` 提供同一 ELF 的新导出。新增30个入口，合计47个支持入口；本组457条原指令、1828字节已逐条与源 ELF 比对。按相同入口／长度／原字节规则计算的本组绑定 SHA-256：

```
9b0670e530d7daba24bd271cdd634c7558247a396f30d2ee9d6f1422c73ee1fd
```

这批不需要图形、音频、SDK或旧VM模型。`a3` 是原寄存器参数；默认0保留已有调用兼容性。

| 原入口 | 恢复行为 | 返回值定义 |
| --- | --- | --- |
| 10D3D0、10D3E8 | self+(a1<<4)+E4，纯地址计算 | signed32地址位型 |
| 10D750 | 以self+D4为索引，取标签记录name地址 | 尾调10FA68的record+8 |
| 10DAE8 | 原JR delay slot明确置v0=0 | 0；不是补的stub |
| 10DAF0 | 从a2标签取offset，以a1选择script block并seek，最后D4=a2 | 10FA28的signed offset保留在v0 |
| 10E630 | load(self+138)+(a1<<3) | history record地址 |
| 10E640 | load(self+13C+(a2<<2))+(a1<<3) | snapshot record地址 |
| 10E658 | 将旧upper pair缓存到170..17C，再写新的upper pair | 旧pair经10E748检查的0/1 |
| 10E708 | 查询缓存valid/id，按可空a2/a3指针输出cached pair | 匹配为1，否则0 |
| 10E748 | 读出upper pair、检查两个sentinel | 有效为1，否则0 |
| 10E878 | 写lower pair，保留两个word其它位 | 原record地址仍在v0 |
| 10E8D8 | 读出lower pair、检查两个sentinel | 有效为1，否则0 |
| 10E9D8 | 不输出pair，仅检查lower pair sentinel | 有效为1，否则0 |
| 10EDC0 | 以self+D4为索引，置word0 bit31 | 原record地址 |
| 10EDF0 | 检查指定record word0 bit31 | 0/1 |
| 10EEA0 | 置指定record word0 bit29 | 原record地址 |
| 10EED0、10EEE8 | 置word0 bit30，前者使用self+D4 | 原record地址 |
| 10EF18 | 检查word0 bit30 | 0/1 |
| 10EF48、10EF60 | 置word1 bit24，前者使用self+D4 | 原record地址 |
| 10EF90 | 检查word1 bit24 | 0/1 |
| 10EFF0 | 检查word0 bit28 | 0/1 |
| 10F100 | self+148减1，保留32位回绕 | 原v0未写 |
| 10F898 | load(load(self+CC)+(a1<<2)) | LW符号扩展的label record地址 |
| 10FA28 | 标签record+4读取offset | LW符号扩展 |
| 10FA68 | 标签record+8计算name地址 | signed32地址位型 |
| 10FAB8、10FAC0、10FAC8 | 清零／读取／写入self+168 | 读取为LW，其余原v0未写 |

一个history record占8字节：word0低14位是lower index，bits14..27是upper index；word1低5位是lower selector，bits5..9是upper selector。两组分别以index=`0x3FFF`或selector=`0x1F`表示无效。这里的upper/lower只描述布局，不擅自赋予尚未恢复的剧情语义。

10E658先写self+174=id和self+170=1，再调用原10E748语义，把旧upper pair写入self+178/+17C，最后修改原记录。10E748与10E8D8在任何输出前缓存word1，但输出后重新读word0进行有效性检查；输出指针与记录或缓存字段重叠时，这一读写次序会影响结果。10E708的id比较使用完整64位a1与LW符号扩展值；不能简单截断a1。原记录查询函数在伪C中缺失的a0/a1参数均按JAL指令现场恢复。

## 第三批：标签桶、名字复制与history snapshot

新增18个ScriptData入口，合计65个。共享libc实现来自 `analysis/ghidra/vm-dependencies-v1/functions/{001fdb50,001fda0c,001fc524}.json`，分别是strcpy、strcmp和memcpy；已支持的1FDC64 strlen移入同一模块。以上名称只描述恢复行为，没有调用宿主libc代替原实现。

| 原入口 | 恢复行为／返回值 |
| --- | --- |
| 10D4C8、10D590 | 复制名字至self+E4+(a1<<4)，构建选中block+434文本包；最终SLTU的v0为0 |
| 10DB48 | 以selector/name定位offset并seek；普通名更新D4且返回u16 id，首字符`_`的名保留D4并返回offset |
| 10DC30 | 检查record word1 bit24为0，且word0 bits31、28同时为1 |
| 10EE18 | 从名称找record id，经lower-history pair定位其标签名；pair无效返回0 |
| 10EFC0、10F018 | 名称解析为id后分别检查word1 bit24／word0 bit28 |
| 10F070 | 将history复制到self+148选中的snapshot，递增stack index，返回最终index−1 |
| 10F0C0 | 先递减index，再从对应snapshot复制到live history；返回memcpy的原目标指针 |
| 10F628 | 原byte hash：32位移位相加、8位计数器，最后fold为8位 |
| 10F678 | 每个block的256个非零bucket相对偏移加block地址；block+430无条件加block地址；v0未定义 |
| 10F6E0 | 按block／bucket／record顺序分配u16 id，首字符`_`标FFFF且不计数，计数写self+C8；v0未定义 |
| 10F820 | 在指定selector桶中找到已存在的label，返回record指针 |
| 10F8B0 | 指定selector中label存在返回1，否则0 |
| 10F938、10F9B0 | 搜索前32个非空selector；前者返回bool，后者返回selector或−1 |
| 10FA48、10FA88 | 按selector/name找record，分别读取signed LW offset／unsigned LHU id |

标签block地址来自 `load(self+8+(selector<<2))`，bucket地址来自 `load(block+30+(hash<<2))`。record+0是u16前进字节数，+2是u16 id，+4是offset，+8是NUL结尾名字。stride=0的最后一条仍需先比较名字／分配id，然后才结束。10F820调用方必须保证名字存在；原函数没有miss出口，零stride不匹配会无限循环。宿主在null bucket或terminal mismatch明确抛错，这是非法输入的终止边界，不伪称源函数会返回错误码；其余可查询入口仍按原逻辑返回0／−1。

10D4C8先执行名字复制，再加载选中block，填充12个`0x21`字节；随后每次写入前重新调用原strlen，最后写`0x1B`和`0x03`。不把长度预先缓存，也不额外截断到12字节。合法游戏数据的长度约束由调用方负责，越界访问由GuestMemory拒绝。snapshot复制保留先读size/live地址、再写index、最后读取snapshot指针的原指令次序，不提前读目标规避别名。

libc对齐与边界：

- strlen按初始地址选择16字节、8字节或逐字节读取。
- strcpy按源与目标共同对齐选择16或8字节块复制，含NUL的最后块改为逐字节写入，包括NUL。
- strcmp保留对应块读边界；不相等时退回逐字节比较，返回两个无符号字节之差的signed32位型。
- memcpy仅在初始count≥32且双方16字节对齐时使用两次有序16字节传送，之后8字节和byte尾部；其它情况逐字节。第一块写入发生在第二块读取之前。count最初以原64位SLTIU比较，之后按ADDIU的32位回绕与符号扩展更新。
- 所有复制都前向进行，保留原重叠传播，不承诺memmove语义。块先读到本地数组再写，可保留单次LQ/SQ或LD/SD内部的读取快照。没有实现MMIO／并发修改／PS2栈别名，读错可能保留此前写入；不承诺回滚。

新增18入口415条指令／1660字节与源ELF逐条相符，本组绑定SHA为 `263b5b983930cb415d0bdacfe916cbb26772f5b0930586e46815cdca218ecc60`。三个新libc函数194条指令／776字节的绑定SHA为 `51dbef9270954f0db8bfd1558bb7a9c66933e2b9c6539ac2f0a3f289ea2ea1e6`。libc的16字节字符串MMI路径目前仍只有静态恢复，不能因C++运行成功而称其原机器码oracle通过。

## 指令优先于伪代码的细节

- LW／SLL／ADDIU／ADDU／SUBU保留低32位并符号扩展到低64位GPR；C++实现使用无符号位运算，没有signed overflow UB。比如读取BE字节 `80 AA BB CC` 返回 `FFFFFFFF80AABBCC`。
- 读取器最初BEQ和循环SLTU使用原64位输入及GPR低64位。Ghidra显示的 `uint param_2` 不能作为丢弃a1高32位的依据；零长度不访问self。读取超过4字节时仍保持原32位移位截断行为。
- 10D610／10D788先写新游标，再读取block/base。实现保留这一顺序，连游标字段与索引表发生别名的受控测试也不换序。
- 10D638的伪C签名是void，但原 `10D678 j 10D610` 实际返回offset；0标记推进3字节，其它标记推进1字节。
- 原strlen按指针对齐选择16字节LQ、8字节LD或逐字节LB路径。实现保留这些读取块的边界，再定位第一个NUL；因此不会因使用宿主strlen而改变跨内存边界的访问范围。16字节路径的MMI零字节检测仍需独立机器码oracle覆盖，不能仅凭成功伪C视为已验证。
- 原void入口的v0是不变，不是零。本接口没有incoming v0，宿主返回0只作无返回值占位；差分中这些入口只比较规定的内存写，不把0当原结果。原栈帧保存ra/s0等由宿主调用约定取代；本API不模拟PS2栈帧或所有易失寄存器。

支持范围是本GuestMemory中的有效数据和结构访问；没有实现整个EE的地址别名、MMIO、TLB和地址异常。已知入口的无效RAM操作会由GuestMemory抛错，可能保留异常前的合法写入，未声称事务回滚。

## 明确未恢复的入口

以下入口在进行guest写入前抛出异常，绝不以返回0或NOP替代：

| 入口 | 仍缺的闭合依赖 |
| --- | --- |
| 10D868 | 多个状态、历史及资源回调；增加a3接口不代表这些依赖已闭合 |

还未加入的history遍历、带日志的标记、字体／资源／菜单状态和分配器调用继续拒绝。已确认的依赖边界包括：10EAD0→19C868及原第五参数t0；10ECA0→19CB50／10FB38→113468→117560→104E10；10DC80／10DFD8→10FB38、111560、11F778、1114F0、101190、17AA90、17AAD8、101230；10F768→17A560 allocator；10F110／10F260→11DAC0 singleton及11E498／11E4B0资源方法。没有用固定返回值、伪分配器或NOP闭合这些图。

其它未知入口同样拒绝。原函数导出尚不等于所有外部行为已恢复。

## 当前验证状态

第一版16入口已用项目内Zig0.15.2实际编译。11项定向native smoke通过：BE符号扩展、零长度不读非法self、10D638两条分支的真实offset、负游标偏移、LW符号扩展、先写游标再读base的别名顺序，以及当时4个未闭合入口拒绝。测试在主线程binary probe上执行，临时输入已清理；这些是指令导出的定向检查，**不是原机器码差分结果**。

独立原始指令oracle由另一任务使用Ghidra/SLEIGH执行，不从C++或旧Python模型计算expected。主线程已完成初始17入口的差分：

- `analysis/ghidra/oracle-readers-v1/cases.jsonl`：470/470通过；报告 `analysis/native-core/diff-20261030-091946-e06eba.json`。
- `analysis/ghidra/oracle-strings-v1/cases.jsonl`：56/56通过，包含不对齐逐字节及mod16=8的LD路径；报告 `analysis/native-core/diff-20261030-091945-322c5e.json`。
- `analysis/ghidra/oracle-history-v1/cases.jsonl`：809/809通过，覆盖新增30入口；报告 `analysis/native-core/diff-20261030-093252-5d017f.json`。包含record0/+4互别名、同一输出、self+178/+17C缓存别名，以及E708高位id比较。累计47入口、1335个真实机器码样本通过。
- 16字节对齐MMI路径的独立oracle在原地址1FDC98的pcpyld遇到未实现CALLOTHER；`analysis/ghidra/oracle-mmi-probe-v1`保留失败，不作为通过fixture，也未填补模拟stub。该路径目前只有源指令审查，未获上述差分覆盖。

第三批的独立原机器码oracle已完成：`analysis/ghidra/oracle-tables-v1`的18入口460/460返回，`analysis/ghidra/oracle-libc-v1`的4个libc入口292/292返回。包含scalar/LD字符串路径、label hash和碰撞链、首字符`_`、u16 id／signed offset、snapshot复制与原次序重叠传播；memcpy的原LQ/SQ实际可执行。5项产物审计通过，覆盖源SHA、逐步原指令、所有RAM写窗口和失败门禁；详情见 `tools/ghidra/TABLES_ORACLE.md`。这些是原代码oracle成功，尚不自动等于新增C++差分通过。

三个新MMI探针分开存入 `analysis/ghidra/oracle-tables-mmi-{strcpy,strcmp,template}-v1`，分别在1FDBA0、1FDA5C、1FDC98的原pcpyld实际失败，runner正确返回验证exit2；未计入成功样本。没有任何本批高层入口必须依赖MMI才能得到基础合法样本，但16字节对齐字符串分支仍只有静态恢复。编译／native差分由主线程统一执行。
