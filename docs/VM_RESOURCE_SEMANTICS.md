# 资源 handler 的解析、重试与切换契约

证据 `VM-RESOURCE-001`，见 `analysis/vm_resource_semantics.json`。工具 `tools/vm_resource_semantics.py` 绑定主 ELF SHA-256 `50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160` 和 sn4g 脚本 SHA-256 `f0a20139375fadff7e5eb7f10c33f1bd503b4e265752a773035f675d99b628f3`。读取标准库静态证据，未执行目标、启动模拟器或加载资源。五类完整 vtable、每类 25 槽直接调用、36 个原指令区域、原始文件偏移和范围哈希均保留；38 项独立测试通过。

本片段提供可执行的默认上下文 slot15 契约，不包含资源解码器、场景程序 VM 或播放后端。`ResourceState` 是引用状态容器，调用者必须从真实初始化／存档状态填入字段；其 Python 默认值仅供模型测试，不能代替原版完整初始化。

## 读取规则

72、73、74 都先调用 `0x10D638`：读一个头字节，非零只跳过此字节；零则再跳过两字节。之后 `0x10D680` 返回当前位置 C 字符串并将主游标前移 `strlen+1`。

因此这三种 handler **不按长度头决定下一指令位置**，而是推进至 NUL 之后。工具同时保留声明长度、实际字符串长度及是否一致；防御性边界／最大字符串长度是本工具的校验，不冒充原版具备相同检查。标识保留为原始字节；ASCII 解码只是方便查看，不把名字直接当作文件路径。

开场实际记录：

| 文件偏移 | opcode | 标识 |
| --- | --- | --- |
| `0xA18C5` | 73 | `pr0000` |
| `0xA18CE` | 74 | `pr0000_00` |
| `0xA18DB` | 74 | `pr0000_10` |
| `0xA18EC` | 73 | `pr5011m` |
| `0xA18F6` | 72 | `pr1011` |
| `0xA18FF` | 74 | `pr5011m_00` |

以上六条与 `opening_instructions` 的原始分帧边界逐项相等。它们是静态字节位置，不代表已观测执行顺序；SPK 内容／依赖映射由独立资源工具负责。

## 72：请求接受与加载完成不同

构造器 `0x127510` → vtable `0x224358` → slot15 `0x127788` → helper `0x127520` → provider `0x11DC40`。slot15 将 a2（opcode 开始的块内偏移）传给 helper。

1. `0x137350` 判断能否发出请求；未就绪时返回 0。
2. 就绪时调用 `0x11E310(token, mode=1)`，令 provider `+8=2`，返回 1。
3. 外层 handler 将 provider 的 0 解释为「重试」：主游标回到 opcode 开始，handler 返回 1；provider 的 1 则前进至字符串末尾，handler 返回 0。

72 在请求成功发出后即前进，并未在这里等待完整读取／解码／播放。不能将它实现为阻塞直至视频播放完毕。

## 73：两阶段加载状态

构造器 `0x127C10` → vtable `0x224438` → slot15 `0x127E10` → helper `0x127C20` → provider `0x11DCF8`。默认槽每次执行先调用 `0x114A68(manager+0x330)`，即 manager `+0x71C=1`，包括重试。

| provider `+8` | 行为 | provider 接受结果 |
| --- | --- | --- |
| 0 或 2 | 若 `0x137350` 就绪，调用 `0x11E310(token,0)` 并设 `+8=1` | 本次始终为 0，外层重试 |
| 1 | 若 `0x135618` 未完成则保持等待 | 0 |
| 1 且完成 | 将 provider `+0xC` 复制到 `+0x10`，调用 `0x135660`，再设 `+8=0` | 1，外层前进 |
| 其他值 | 不启动、不完成 | 0 |

`0x11E310` 用 `0x101B58` 解析标识，模式 0/1 分别调用 `0x137578` 的不同 flag；它最后把查询返回的组标识保存到 provider `+0xC`。`0x11E3B8` 在完成时把该标识复制至 `+0x10`，后者用于后续 cue 查找。具体请求队列、registry 和字节资源需要后端实现。

## 74：查找 cue，失败则回退请求并重试

构造器 `0x1278D8` → vtable `0x2243C8` → slot15 `0x127AE8` → helper `0x1278E8` → provider `0x11DDA8`。

默认槽每次执行 `0x114A78(manager+0x330)`：

```text
old = manager[+0x720]
manager[+0x718] = (old == 0)
manager[+0x720] = old + 1
```

这些修改发生于**每次重试**，不是只在预解析时执行一次。

provider 的 `0x138F68` 在此构建恒返回 1。接着调用 `0x101CA8(registry=provider[+4], group=provider[+0x10], token)`：

- 找到 cue：调用 `0x138E10(cue,token)`，该函数继续调用 `0x138C90` 和 `0x1395A8`。外层再调用 `0x10F110(script,token)`，经 `0x11E498→0x101928` 取得 token 索引，写 script `+0xE0`，前进并返回 0。
- 没找到 cue：`0x101DC0(registry)` 提供一个回退名字，交给 **provider73 helper**；无论这个 helper 本次是否完成，74 都返回未接受，外层回退 opcode 并返回 1。下次重新查 cue。此路径没有调用 73 的默认槽，因此不会附带执行 73 的 manager `+0x71C=1`。

激活 cue 可能运行场景程序，不能等同为换一张背景图片。`0x101DC0` 返回名字的完整 registry 语义尚未还原，因此工具只称其为回退名字。

## 可接入接口与依赖

```python
from vm_resource_semantics import ResourceState, step
result = step(script_buffer, state, callbacks)
state = result['state']
```

`state.cursor` 是传入字节缓冲区的索引；原版块选择／相对游标必须由调用者包装，不能把文件偏移直接写进 PS2 指针。返回 0 表示此 handler 接受并前进，返回 1 表示重试本 opcode；这不是资源展示完成证明。

callbacks 以原函数地址为键，全部必须显式提供：

| 地址 | 接口 |
| --- | --- |
| `0x137350` | `request_ready() -> bool` |
| `0x11E310` | `begin_request(token_bytes, mode) -> pending_group_id`；负责原查询和发出请求副作用 |
| `0x135618` | `request_completed() -> bool` |
| `0x135660` | `finalize_request()` |
| `0x101CA8` | `lookup_cue(active_group_id, token_bytes) -> cue 或 None/0` |
| `0x101DC0` | `fallback_name() -> bytes` |
| `0x138E10` | `activate_cue(cue, token_bytes)` |
| `0x101928` | `cue_index(token_bytes) -> int` |

没有实现的 callback 会抛 `UnresolvedDependency`。报告中的两步 73 演示使用明确标注的合成 callback，仅验证状态机分支，不能称为真实加载成功。工具不附带伪资源、默认成功后端或未知操作的空实现。

其他上下文槽的原指令和直接调用已留在 JSON；这里仅执行 slot15。主剧情到角色选择仍需要资源 program VM、输入／等待上下文、跳转和状态保存等工作，不能由这三种请求契约替代。

## 7F：图形选择的实际目标与恢复协议

实际指令位于 sn4g 文件 `0xAD615..0xAD660`，75 字节，SHA-256 `b7f19b334111b7f3bacd4a652e934256e89d24d6d41c8b7327ca0d2ac33d9adf`。字节开头为 `7F 49 05`：头后的 05 是选项数，每项由一字节 selector 和 NUL 终止 label 组成，末尾再有一对 fallback。原处理器 `0x12E180` 使用 C 字符串推进游标，声明长度只被跳过。报告保留每个目标的原始 symbol 记录与解析地址。

| index | selector | 目标 label |
| --- | --- | --- |
| 0 | 17 | top00_1200 |
| 1 | 17 | top00_1300 |
| 2 | 17 | top00_1400 |
| 3 | 17 | top00_1500 |
| 4 | 17 | top00_1600 |
| fallback | 17 | top00_1200 |

7F 的 payload 只有这些目标，没有背景图引用。背景和角色画面的来源仍须由 scene program 证据确定，不能从 label 名字推定。

构造器 `0x12E170` 安装 vtable `0x225158`；slot15 `0x12E530` 转至 `0x12E180`。解析完成后先将 variable 4 的值写入 variable 0x19B，再调用 `0x1AC690`。后者保留为有副作用的未解析依赖。

manager `+0x808=0` 时进入 `0x119A18`：

1. choice `+8` 保存旧 manager context；`0x1133F0→0x1163E8` 将 manager `+0x294` 起始的计时状态压栈。随后 `0x111550(0)` 设置 `+0x29C=0,+0x294=0`，安装单例 `0x120880` 的 context。
2. 每项 selector/label 存在 choice `+0xC/+0x10+index*8`，fallback 在 `+0x3C/+0x40`。selected `+4=-1`，done `+0=0`。
3. `0x135BD8` 注册外部图形选择，`0x1114F8` 重置字体／manager；active `+0x50=1`，保存 script D0、D4、post-7F 相对 cursor 至 `+0x44/+0x48/+0x4C`。handler 返回 1，**不退回 7F opcode**。

选择 context 的 vtable `0x223A50`，tick 为 `0x120900`。它先检查 manager `+0x18` 对象的 `0x119A10`；为真时使用 `0x119820`，否则调用 `0x119B60`。当前模型仅实现后一分支，前一分支必须由集成端保留，不能直接忽略。

`0x119B60` 在 done=0 时返回 0；done 非零时先调用 `0x1114F8`，再选择目标。selected=-1 使用 fallback，其余值索引选项。随后 `0x10DAF0` 恢复 saved D0/D4、`0x10D700` 恢复 saved cursor，然后调用 `0x10D868`。普通选项传 flag=0，fallback 传 flag=1。最后 `0x1133D0→0x116470` 弹出计时状态、恢复旧 context、active=0，返回 1；context tick 将此完成值取反。

manager `+0x808!=0` 是另一条自动路径：按原 index 调 `0x14BCC0` 过滤选项，无条件附加 fallback，再由 `0x115E58` 选 index；直接 `0x10D868(...,flag=0)`，handler 返回 0。这里 fallback 的 flag 与普通 UI 取消结果不同。`0x14BCC0` 对 unsigned index≥4 固定返回 0；较小 index 查 `0x22C2B0` 表。模式变量 4 的上界为 8，负值行为未规范化。`0x115E58` 优先从 `0x10F018` 返回 0 的候选中选择，多个时调用 `0x17AA28`。读状态与随机源仍是外部依赖。

接口为 `parse_graphical_choice`、`graphical_choice_begin`、`graphical_choice_poll`。前端必须显式写入 done/index；没有默认 UI 结果。防御性索引和容量检查比原始实现严格，并不声称原版有同样校验。

## 6C：普通 mode1、extra0、flags0 的最小执行合同

此处进一步限定正常 default slot15、manager `0x113368` 谓词为 false、manager `+0x28` 对象 `+0x10=0`、manager `+0x808=0`。其他模式或上下文由模型抛出 `UnresolvedDependency`。当前原脚本样本仍是 `0xA259C` 的两个照片选项，mode1、extra0、flags0。操作数及文本前缀见 `docs/CHOICE_BRANCH.md`。

**确认选择时的旧 selector 通常是原剧情块，不能假定为运行时模板 32..41。** 证据在 `0x118338` 的末项 preview16 路径：

- `0x118444/0x118448` 用 choice `+0x10` 恢复 ScriptData D0。
- `0x118450/0x118454` 用 choice `+0x14` 恢复 D4。
- `0x11845C/0x118460` 用 choice `+0x18` 恢复相对 cursor。
- 此时已经进入 `0x11E6C8` 交互 context，之后才等待输入和确认动画。

提交 `0x118D68` 调用 `0x10D868` 时，后者 `0x10D958` 检查 old D4!=-1，`0x10D960` 检查 unsigned old selector<32。普通块满足时会进入 history/read-state 路径，包含 `0x10E658`、`0x10ECA0` 以及后续有条件记录。运行时模板只用于预览，不能成为省略这些调用的理由。这里委派已有 control/read-state 模型，不复制或猜测历史记录格式。

`choice6c_setup` 实现该限定路径的以下顺序：

1. handler `0x125778` 的 `0x19C910` hook。原参数是 `0x10D750` 得到的当前 label 字符串和 alternate-context 标志；适配器接受明确的 ScriptPosition，再解析对应字符串。这个 hook 包含可配置 callback、global choice/read bookkeeping，不能用空调用替代。
2. `0x118200` 保存字体主对象 virtual slots0/1 的结果至 choice `+0x16C/+0x170`；`0x1186E8` 保存 ScriptData D0/D4/post-operand cursor、旧 context、模式和选项。普通分支 `+0x1C8/+0x1CC/+0x1D0=0`。
3. `0x10EDC0` 清 pending 状态；若 `0x117560(manager+4)` 为 false，调用 `0x10ECA0(savedD4,1,0)`。这些状态也属于持久化语义。
4. manager `0x113448→0x17D380`；字体 `0x16A788` 将 virtual slot4 再 slot2 的值推入 font `+0x2C` 栈，`0x16A6B0(0,0)` 设置控件，`0x16AA98` 设置 128/128/128、0/0/0。
5. 写选项 labels `+0x1C`、selectors `+0x44`、signed flags `+0x6C` 数组；mode `+0xC=1`、count `+4`。extra0 对应 `+0x18C/+0x190/+0x194/+0x198=0`。
6. `0x16A8C8(0,0)` 执行坐标更新及 secondary alignment；保存首项 virtual XY 至 `+0x78/+0xA0`，render index `+8=0`、selected `+0x168=0`，保存字体控制至 `+0x184/+0x188`。切 preview context `0x11E958`，调用 `0x10D7D0(0)` 选择 runtime block32。6C handler 返回 **0**，主循环将继续使用新 context。

`choice6c_preview_ready` 是**预览完成后的尾部 checkpoint**，不伪装执行完整 preview。调用者必须已按原 preview allowlist 处理目标、glyph、04/16、highlight/prompt 等动作，并提供每项 XY 及两组 glyph start/end。函数只实现 `0x118428..0x11847C`：切交互 context、`0x16A7E8` 逆序弹出 font 控制、恢复 D0/D4/cursor、`0x19CAD8(0)`。传入不完整记录会报错。

`choice6c_commit` 要求调用者已经完成输入确认及 `0x118288` 等开始过渡的副作用，并将 phase 设为 confirming。它不是省略确认流程的授权。此后：

1. `0x11E608` 等待字体 `0x16BA10` 为 0；非零继续等待。
2. `0x118250→0x16A950` 恢复预选择字体 XY 和 secondary alignment。它只恢复字体，**不恢复 ScriptData**。
3. `0x117EE8` 对选中项两组 glyph 范围传入 float0，随后切默认单例 `0x120280`，用选中的真实 selector/label 调 `0x10D868(...,flag=0)`。
4. `0x11A380` 设置 manager `+0x28` 对象 `+0x14=1`。过渡 context tick 本次仍返回 1；下次按已安装的默认 context 执行。

返回的 checkpoint 包含可序列化的选择字段，但**不是完整原生存档格式**。恢复选择至少还需保存：当前及 saved ScriptData 位置、context/phase、选项数组、render/selected index、旧 context 及 alternate flags、font XY/控制栈/活跃 glyph 与每项两组 glyph 范围、history/read-state、`0x19C910` 相关全局记录、manager `+0x28` control object。字体虚方法的值仍用原数值含义，不强行声称全部为屏幕像素。

所有 callback 均为带地址标签的**语义适配接口，不是原始 C ABI**。调用 `0x10D868` 的适配器必须执行历史副作用并返回 `ScriptPosition`；工具不接受只修改画面却缺失返回位置的后端。缺失依赖立即阻断，测试中的空回调均明确是合成 fixture，不能作为游戏实现。

复现与独立测试：

```powershell
python tools/vm_resource_semantics.py
python -m unittest discover -s tests -p test_vm_resource_semantics.py -v
```
