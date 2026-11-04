# 从原程序恢复游戏

原盘的 `SLPM_664.52`、三份 ScenarioLink 脚本和对应资源表决定游戏行为。用 REA 与 Ghidra 的 R5900 工具链提取原函数、调用关系、数据结构和间接调用目标，在 `port/core/` 中以 C++ 恢复实现。原作者的工程、类型和变量名没有随光盘交付。恢复结论要标明函数原地址、输入状态、所读和所写的字节以及验证方式。[工具链](REA_PS2_ADAPTER.md) · [当前覆盖](PC_PROGRESS_2026-10-31.md)

PS2 硬件行为可对照本项目所用的 PCSX2 2.8.2。软件 GS 绘制器给出源色、目标色、系数、取整、钳位及通道写掩码的处理顺序，可用来核对游戏送出的 GIF 包。比如闪光的工厂、各阶段持续时间和绘制请求来自原 ELF 的 `0x17E0C0` 等函数，最后的整数混色再与 GS 实现对照。[PCSX2 v2.8.2 软件绘图实现](https://raw.githubusercontent.com/PCSX2/pcsx2/v2.8.2/pcsx2/GS/Renderers/SW/GSDrawScanline.cpp) · [闪光原指令对照](../analysis/native-core/state-calls-20261031-035154-1d2e84.json)

项目的 Ghidra 任务用 `--process` 重用已有 EE 数据库，包括已辨认的间接回调。REA 的本地适配器则在私有目录导入同一指纹的 ELF。对 `0x1B42A8`，两条路径都定位到 244 字节函数和向 `0x1B43A0` 的尾调用；目前没有证明 REA 自动继承主数据库内另行建立的符号或回调。遇到 VU 特殊指令时，另行标注比较所用的宏语义与核验范围。[主库函数](../analysis/ghidra/bgm-device-transition-v1/functions/001b42a8.json) · [REA 结果](../local/dependencies/rea-ps2/runs/2026-10-31T09-12-05-636Z-function/summary.json)

PS2Recomp 从原盘 ELF 批量生成 C++。雪迹山庄的带状特效已把创建、更新、绘制和释放四个入口及四个辅助函数编入 Windows 玩家。原任务池、浮点运算和显示场有独立的宿主适配。固定抽查原表前 100 个槽位，其中 33 个不同的非空工厂有 27 个已编译为 Windows x64 目标文件。后续按模块分别登记函数边界、外部调用、编译与行为验收。ps2-port-engine 保留作设备接口参考。[生成与运行记录](PS2_RECOMP_EVALUATION.md) · [工厂抽查](../analysis/ps2recomp-factory-survey/report.json) · [ps2-port-engine](https://github.com/danielgomesvieira2000/ps2-port-engine)

## 原盘冷启动

Windows 玩家在启动、继续进度和场景切换时直接挂载日版 ISO。原 ELF 的 `0x160510` 调用 `0x164A50`，延迟槽把参数补为 `0x22D108`，这里存的是 `cdrom0:disc.fad`。原读取函数请求 `0x30000` 字节，并以 `0x20` 字节为步长扫描索引。原生提供器核对卷描述符、根目录和这份主索引的哈希，再按父目录、扇区和长度定位文件，每次交付资源均核对实际字节的 SHA-256。全盘九个脚本和字体文件头仅与主索引的共同基址 LBA 1000977 一致。盘内另两份索引没有符合这一读取方式的共同基址。[扇区扫描与小游戏调用者](../analysis/native-core/disc-archive-57/REPORT.md) · [原版调用与延迟槽](../analysis/decompiled-ee/shard-060.asm) · [原读取函数](../analysis/decompiled-ee/shard-062.c) · [原生读盘实现](../port/core/retail_disc.hpp)

三份原脚本都从各自的 `top00_0000` 进入真实 manager 分派。首条 `0x22` 的 C++ 执行结果已在每部两种初始堆条件下与 R5900 全程对照。执行包括条件前瞻、字体偏好、原字形池、回看和标签记录。随后 `0x73` 预载场景，`0x74` 解释并提交原 cue。第三篇已进入序章并显示 `pr01_0010` 的两行提示，首个剧情互动等待及其后的进展以实际运行记录为准。[全指令差分](../analysis/native-core/cold-page-differential-20261031-070133-1c69dc.json) · [原生玩家窗口](../analysis/native-core/player-window.json)

## 验证边界

- **冷启动**记录原文件指纹、入口、指令地址、真实分支和首个未恢复函数。只把从该入口实际到达的状态计为剧情进展。
- **定点对照**可从合法原版存档或 RAM 初态验证某个函数、选项、字形或帧。记录起点与结束位置，独立比较原指令执行时的字段、资源请求和输入消费。定点用例覆盖的页面与冷启动覆盖分开统计。
- **平台接入**在核心提交一帧后呈现原始资源、文字和菜单。未知操作报告入口并保持可重试。选择映射成原控制动作，分支目标和已读标志仍由核心决定。普通缩放和扫描线在原图层处理。
- **本地化**用脚本身份、文本 ID 和原等待事件确定当前可揭示的单元。首次可见帧就使用选定语言。中途切换重排本帧可见内容，保持游标、计时、待决选择、语音和动画连续。发布前以完整初稿作中文全局校对。[界面验收](ui/UI_CONTRACT.md)
