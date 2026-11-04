# PS2Recomp 与原生核心准备

## 2026-10-31 声音、画面和剧情返回

本阶段六组生成清单合计 57 个函数体、2,016 个原指令字。生成器从已核对指纹的日版 ISO 取出启动 ELF，以 Ghidra 的 R5900 边界驱动 PS2Recomp。原指令和延迟槽在生成时逐地址回查；移植侧分别接入资源、声部、菜单和绘图。清单统计包含任务字段设置函数。

| 原模块 | 生成函数 | 已取得的对照 |
|---|---:|---|
| 声音参数 | 4 | 17 个音高输入的 EE 原始返回位全部相同。另有 123 个声像、音量、音高寄存器及渐变样本逐位相同。声部更新对照固定了三个设备 RPC 返回。[音高](../analysis/native-core/sound-pc-11/true-ee-pitch-comparison.json) · [声部参数](../analysis/native-core/sound-pc-11/true-ee-parameters-comparison.json) |
| 渐变滤镜 | 7 | 两组颜色、纯白与彩色两种纹理、两个隔行场，均与独立 PCSX2 软件 GS 回放逐像素相同。[八组 RGB](../analysis/native-core/grade-pc-10/comparison.json) |
| 缩放残影 | 9 | 原函数提交 21 次采样。第三次更新的一组彩色纹理在两个场上 RGB 匹配。GS 对照采用原生函数输出的 UV 并单独验证采样与混合。[绘图输入](../analysis/native-core/blur-pc-17/fixture.json) · [逐场结果](../analysis/native-core/blur-pc-17/gs-comparison.json) |
| 八方向场景滑动 | 4 | 跳转表保留八个目的地址，绘制分别取当前场和先前捕获的场。水平与垂直方向各测一例，两个场的独立软件 GS 像素对照均为零差异。[生成记录](../analysis/ps2recomp-screen_slide/manifest.json) · [四组对照](../analysis/native-core/slide-pc-01/gs-comparison.json) |
| 剧情返回和菜单初始化 | 5 + 28 | 原版选择分派至章末专用菜单对象。香山原盘冷跑到 60,184 帧进入其记忆卡 UI。另已生成卡界面调度函数并逐项对齐其 50 项跳转表、28 个不同入口。该函数的设备与输入服务待接入，未计入前述 57 个函数。[冷跑停点](../analysis/native-core/return-menu-03/sn4g-100000.json) · [原 ELF 与生成分派的逐项核对](../analysis/ps2recomp-chapter-card/manifest.json) |

## 2026-10-31 带状特效进入 Windows 玩家

这次将效果 22 的四个入口 `184690/184760/1847A8/1848B8` 和四个任务字段设置函数编入正式 Windows 玩家。两个不同的原场景命令使用这一实现。扫描三份原 SPK 的 11,086 条 cue 记录后，找到 `mm1320b_10` 与 `mm1350a_00` 两处 `EFFECT_ON(22,180)`。[原盘调用位置与字节](../analysis/ps2recomp-expandband/scenepack-sites.json)

| 检查 | 范围和结果 |
|---|---|
| 自动生成 | 八个函数体、150 条原指令。两次生成的头文件完全相同。一次读取并复核整盘、抽取 ELF、运行上游工具、核对结果耗时 2.83 秒。人工工作集中于八个外部调用目标、EE 运算适配与 GS 合成。[生成指纹与外部调用](../analysis/ps2recomp-expandband/manifest.json) |
| 原 CPU 对照 | 本机 PCSX2 2.8.2 的 EE 重编译器运行原始工厂与更新指令，两个分配叶固定返回样本地址。第 77 次更新首次暴露首个 Windows 候选的高度差。修复加减与整数转浮点后，生产核心的 180 次连续更新、12 个时长样本和 9 个状态样本，共 201 项与原读数相符。[原读数](../analysis/native-core/expandband-ee-reference/actual.json) · [生产核心对照](../analysis/native-core/expandband-ee-reference/production.json) |
| 原绘图命令 | 通过 Ghidra 运行原函数及绘图辅助函数，补充 VU 定点转换后，取得原函数写入 RAM 的 GIF 包。将这些包、原显示环境与剧情底图送入 PCSX2 2.8.2 软件 GS。第 26469 场的两物理场逐 RGB 全部相同，第 26559 场的整幅 RGBA8 哈希相同。合计两张 640×448 画面。此项使用等价输入重放，同场的原机抓取仍待取得。[原始包](../analysis/native-core/pcv-184690-01/draw-packets-v3.json) · [软件 GS 回放与最终候选](../analysis/native-core/expandband-gs-reference/raw-original-cold-trace-CEB3C294-result.json) |
| 原文件冷启动 | 原停点出现在第 26378 场。相同输入下，最终候选在第 26379 场创建任务，第 26559 场完成，第 26805 场释放。到第 36513 场时已确认 956 次等待、选完 16 次，正常停在第 17 次选择。旧停点前的 1365 条可比观测完全相同。[冻结探针与命令](../analysis/native-core/pcv-184690-01/final-cold-run.json) · [最终路线](../analysis/native-core/pcv-184690-01/cold-CEB3C294.jsonl) · [保留的中间场](../captures/recompiled-core/sn2-mm1320b_10-field-26469.png) |
| 批量效率 | 预先取原表前 100 个槽位，含 33 个非空工厂。27 个函数边界可直接导入，批量生成耗时 2.94 秒，三路编译耗时 21.71 秒，产出 27 份 Windows AMD64 COFF。另有 5 个入口缺少独立边界，1 个函数体不连续。这 27 项计至目标文件阶段。[原表、编译参数与逐项结果](../analysis/ps2recomp-factory-survey/report.json) |
| ISO 资源 | 早期工具从原盘读取主 FAD 索引及其中 3844 个文件，逐项对照已记录的资源哈希。后续正式播放器已接入相同原盘成员，并完成独立目录启动、游戏存档续玩和按需解码验证。[直接读盘核验](../analysis/ps2recomp-expandband/iso-resource-read.json) · [独立播放器](../analysis/native-core/iso-pc-01/report.json) |

正式生成可用 `tools/python.ps1 -B tools/generate_expandband_recomp.py` 重复。生成代码的八个函数、其余工厂的编译抽查和端到端进入剧情这三项分别统计。工具耗时只含各自表内的步骤，同一模块缺少旧方法的对照工时。

正式玩家 `9101B0FB…D1D7E07F` 通过标题的继续入口，读回最终探针用正常剧情操作生成的私有槽位。实窗截图保留剧情场景与侧栏。窗口没有内置场号显示，逐场读数以同源探针为准。[存档生成命令与指纹](../analysis/native-core/pcv-184690-01/window-checkpoint-receipt.json) · [窗口操作记录](../analysis/native-core/pcv-184690-01/window-actions.jsonl) · [实窗截图](../analysis/native-core/pcv-184690-01/product-effect-mid.png)

本阶段从 09:57 UTC 开始，10:29 UTC 完成复核，共约 32 分钟，包含生成、人工适配、首次差异修复、回归与两个对话的交接。账户周额度已用从 43% 升至 47%，变动约 4 个百分点，本阶段上限为 10 个百分点。最终 36,513 场的无窗口冷跑耗时 26.46 秒。Astra 已对照原始读数、两份构建收据、像素报告及窗口截图复核 Sol 结论。[Sol 阶段验收](../analysis/native-core/pcv-184690-01.json)

## 2026-10-31 原盘 ELF 到 Windows x64

本项目已编译未修改的上游 PS2Recomp，版本为 `e5636981a1c9de368f6b71e819c3dc188dfedbf4`。驱动只读打开 ISO，验证整盘 SHA-256，解析 `SYSTEM.CNF` 后按 ISO9660 目录读取 `SLPM_664.52`。它把完整原 ELF 与主 Ghidra 数据库给出的边界送入上游生成器。[生成器构建记录](../analysis/ps2recomp-pilot/build/receipt.json)

本次试验选取 `effect_expandband.c` 的原更新函数 `0x184760` 和完成标志设置函数 `0x179C68`。另外列入真实 ELF 启动入口和两对初始化入口/尾块，以满足上游注册表检查。生成器成功输出 7 个地址范围，报告为 0 个桩、0 条未处理指令。启动入口 `0x1B4DB4` 有未解析的间接调用警告。Windows 探针编译链接其中两个目标函数，覆盖 20 条原指令和 4 个延迟槽。两个生成的 C++ 文件未经手改。宿主提供上游寄存器结构、受边界检查的 EE RAM 和回到调用者的哨兵。此试验范围为函数执行；原启动入口、画面、设备和整部游戏仍须分开验证。[生成日志](../local/pc-core/ps2recomp-pilot/20261031T094430194697Z/recompile.log) · [生成的更新函数](../local/pc-core/ps2recomp-pilot/20261031T094430194697Z/generated/FUN_00184760_0x184760.cpp) · [生成的设置函数](../local/pc-core/ps2recomp-pilot/20261031T094430194697Z/generated/FUN_00179c68_0x179c68.cpp)

Sol 以 Ghidra 直接执行原 ELF，独立对照相同输入下的 Windows EXE。8 个单次边界样本和 1 个连续 180 场的样本均通过，共比对 188 次调用。每次包含寄存器、返回 PC 和三段原始内存，首次差异为空；连续序列在第 180 次调用才触发原设置函数。另一次从 ISO 和同一函数表重新生成的 7 份 C++ 均与首份输出逐字节一致。[Sol 独立验收](../analysis/ps2recomp-pilot/validation/report.json) · [重新生成的指纹](../local/pc-core/ps2recomp-pilot/20261031T094653723457Z/generated.json)

在项目根目录运行以下命令可重新生成、编译和执行。每次运行使用新目录，打印新 EXE 路径及 SHA。下面的第二条命令可直接复查本轮已冻结的 EXE，分别输入高度 1、每次减 1、总共 2 场。输出的第一场高度为零、完成字保持原值，第二场才将完成字设为 1。[本轮 Windows 构建与完整编译参数](../local/pc-core/ps2recomp-pilot/20261031T094430194697Z/build.json)

```powershell
.\tools\python.ps1 -B tools/run_ps2recomp_pilot.py
& '.\local\pc-core\ps2recomp-pilot\20261031T094430194697Z\pilot_host.exe' expandband 3f800000 3f800000 2
```

## 2026-10-30 早期编译器实验

以下记录初次评估时的工具状态。[当前 C++ 恢复路线](DECOMPILATION_ROUTE.md)

## 本机工具链

只读检查 PATH 与常见目录，没有发现可用的 `cl`、`clang/clang++`、`gcc/g++`、CMake、Ninja。检查范围包含 `C:\tools`、两处 Program Files 的 Visual Studio／LLVM／CMake、`C:\msys64`、`C:\mingw64`、Scoop、Chocolatey、WinGet 与用户 Programs。Git 可执行文件为 `C:\Program Files\Git\cmd\git.exe`。这不是全盘扫描结果，也不表示其它自定义目录绝无编译器。

采用项目内固定 **Zig 0.15.2 / x86_64 Windows**，先以 `zig cc/c++` 编译独立小核心，暂不要求 CMake、Ninja 或整套 PS2 runtime。来源为 [Zig 官方发行索引](https://ziglang.org/download/index.json)，固定 archive SHA-256：

```
3a0ed1e8799a2f8ce2a6e6290a9ff22e6906f8227865911fb7ddedc3cc14cb0c
```

安装范围为 `local/dependencies/ps2recomp/_evaluation/toolchain/`；下载来源、归档及编译器 SHA 记录到 `_evaluation/toolchain.json`。不安装系统软件、不改全局 PATH；Zig 缓存通过当前进程环境变量置于同一目录。官方下载连接曾无数据进展，因此备用来源限于官方发布的 [社区镜像列表](https://ziglang.org/download/community-mirrors.txt)，仍须匹配上述官方哈希后才解压。

已真实编译并运行 C17／C++20 smoke，两者编译和运行退出码均为0，`_evaluation/smoke-results.json` 的 `ok=true`。输出为：

```json
{"kind":"c-smoke","u32_wrap":0,"pointer_bits":64}
{"kind":"cpp20-smoke","u32_wrap":0,"signed_bits":-1,"float_bits":1065353216,"register128_bytes":16}
```

可直接执行的编译器：

```
./local\dependencies\ps2recomp\_evaluation\toolchain\zig-x86_64-windows-0.15.2\zig.exe
```

项目根目录 PowerShell 编译示例（把输入／输出换成实际核心文件）：

```powershell
$evaluationDir = Join-Path (Get-Location) 'local/dependencies/ps2recomp/_evaluation'
$zigCompiler = Join-Path $evaluationDir 'toolchain/zig-x86_64-windows-0.15.2/zig.exe'
$env:ZIG_GLOBAL_CACHE_DIR = Join-Path $evaluationDir 'zig-global-cache'
$env:ZIG_LOCAL_CACHE_DIR = Join-Path $evaluationDir 'zig-local-cache'
& $zigCompiler c++ -target x86_64-windows-gnu -std=c++20 -O0 -g -fno-fast-math -ffp-contract=off (Join-Path $evaluationDir 'smoke.cpp') -o (Join-Path $evaluationDir 'smoke_cpp.exe')
& (Join-Path $evaluationDir 'smoke_cpp.exe')
```

完整复验入口 `_evaluation/compile_smoke.py` 记录参数、源文件／EXE SHA、stdout和退出码。本机默认沙箱运行编译器曾在写其项目内 `builtin.zig` 缓存时报 `Unexpected`；相同命令在已批准的 `require_escalated` 执行环境中全部通过。失败原日志与结果另存 `compile_*-sandbox-failure.log`、`smoke-results-sandbox-failure.json`，没有用隐藏错误或跳过编译代替验证。工具链功能不等于游戏或PS2语义已通过验证。

## 核对的原仓库版本

已浅克隆 [ran-j/PS2Recomp](https://github.com/ran-j/PS2Recomp)，commit：

```
e5636981a1c9de368f6b71e819c3dc188dfedbf4
```

源码保存在 `local/dependencies/ps2recomp/`，保留原许可证文件。根 CMake 实际要求 **3.21**，C++20；README 的3.20描述较宽。该版本没有 `.gitmodules`，重编译器依赖由 FetchContent 获取：ELFIO 3.12、toml11 4.4.0、fmt 12.1.0、libdwarf 2.2.0、Rabbitizer 1.14.3。

将来单独构建转换工具的最小配置为以下选项，**本次尚未验证整套构建**：

```
cmake -S . -B out/recomp-only -G Ninja
  -DPS2X_BUILD_RUNTIME=OFF -DPS2X_BUILD_ANALYZER=OFF
  -DPS2X_BUILD_TEST=OFF -DPS2X_BUILD_STUDIO=OFF
  -DPS2X_BUILD_RECOMP=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build out/recomp-only --target ps2_recomp
```

CMake／Ninja及五个依赖不是恢复独立小型 C++ 核心的前置条件。本机当前也未配置它们。

## Ghidra 导出实际格式

核对文件：[ExportPS2Functions.java](https://github.com/ran-j/PS2Recomp/blob/e5636981a1c9de368f6b71e819c3dc188dfedbf4/ps2xRecomp/tools/ghidra/ExportPS2Functions.java)，以及 `ps2xRecomp/src/lib/elf_parser.cpp::loadGhidraFunctionMap`。

CSV 固定四列 `Name,Start,End,Size`。Start 为入口虚拟地址，End 为 **exclusive**，地址以 `0x` 十六进制写出；Size 是 Ghidra body 的地址数量。导入器读 Start／End、限制到可执行 section，实际不使用 Size。因此非连续 body 不能只靠 Size 判断；必须另存 body ranges 与原始指令字节。脚本还收集 address-taken／可调用标签等 synthetic `entry_*`，不能只导出函数列表而遗漏回调入口。

伴随 TOML 的 `[general]` 提供 `input`（原 ELF）、`output`、`ghidra_output`（CSV）以及 patches/stubs 等选项。这是**函数边界和配置导出，不是反编译 C 导出**；重编译器仍从 ELF 读取 R5900 指令。真实 Ghidra 伪 C 可以作为恢复可读核心的证据，但不能直接塞入这个 CSV 接口。

原导出脚本默认 `patch_cop0=true`、`patch_cache=true`，并自动分类部分 runtime stubs。函数级差分基线必须逐项审阅，不能把这些替换当原行为。`untracked_stubs` 在该版本配置解析中作为 entry-point hints 处理；它不表示已实现外部函数。

## C++ 核心隔离与差分执行

生成器 `function_emitter.cpp` 的函数接口是：

```cpp
void function(uint8_t* rdram, R5900Context* ctx, PS2Runtime* runtime);
```

`R5900Context` 含128位 GPR、HI/LO、PC、delay-slot、FPU／VU 状态。`PS2Runtime` 头部直接依赖 GS、VU、音频、pad、VFS、IOP；其完整 CMake 又引入 raylib、FFmpeg 和可选调试 UI。因此现成 runtime 并非可直接分离的无图形“纯核心库”。`PS2X_BUILD_RUNTIME=OFF` 可单独构建翻译器，但不自动提供可执行的最小 guest runtime。

建议先交付独立的 C++20 核心和 CLI 差分测试，再通过稳定 C ABI 接前端。真实函数恢复时采用以下边界：

1. 每个函数记录 ELF SHA、VA／body ranges、原指令 SHA、Ghidra版本／导出输出与调用依赖。
2. 输入显式包含原32位地址空间、little-endian内存、寄存器／gp／sp／ra、受调用函数结果。原指针不可直接变为宿主指针；保留整数宽度、移位、溢出和 delay-slot 语义。
3. 对同一初态运行“恢复核心”与源指令执行参考，比较返回值、实际写内存、回调顺序及其参数；以少量真实原版 trace 交叉确认。原指令执行可作为独立对照。
4. 初期选择已收到真实反编译输出且没有硬件副作用的小函数。未恢复的调用、未覆盖指令、越界访问必须明确停止，禁止用返回0或 NOP 令测试表面通过。
5. 使用 Debug／无 fast-math／不融合FMA；完整上游 MSVC Release 选项包含 `/fp:fast` 和 AVX2。其 FPU 测试也显式标出部分硬件向量的末位或 denormal 差异，因此不能把一次编译成功当原PS2算术逐位等价。

上游提供 `MissingFunctionPolicy::Stop`，而默认是 ContinueToTarget；若使用其 runtime 做 oracle 应明确设 Stop。已有上游测试包含源码生成形状、运行时以及部分硬件浮点向量，但本次没有执行它们，也没有发现可直接输入本游戏函数快照的一键差分框架。函数级 oracle 的内存／外部调用适配仍需本项目实现和验证。
