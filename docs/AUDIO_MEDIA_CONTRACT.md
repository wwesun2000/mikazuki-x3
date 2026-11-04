# 原声音频参数和 MMV 播放契约

可执行合同：`tools/audio_media_contract.py`；证据：`analysis/audio_media_contract.json`；13 项测试通过。它接收原 cue 参数，不驱动原版 UI。新提取的原盘 `IRX/SSDV.IRX` 含符号 `ssdvSetNoteon`、`ssdvSetNoteModify`、`pantable` 和 `SSDV_SE_TABLE` 调试类型，直接佐证此前恢复的 56 字节记录。提取来源及哈希在 `analysis/audio_irx_extraction.json`。

## 接口与参数

`play_contract(record, args, stereo_output=True, active_loop_ids=(), following_queue=())` 输入六个原始参数 `[id,volume,transition,pan,pitch,completion]`。输出两个 SPU voice 的源流编号、启动 update、音量斜率、左右增益矩阵和等待时间。已有循环 ID 返回 `no-op-existing-loop`：不重启，不更改已有参数。故 `537002` 从 `pr0000_10` 延续到 `pr5011m_00`，不能切场景就重播。

`change_contract(command,args,current)` 恢复 STOP / CHANGE_VOLUME / CHANGE_PAN / CHANGE_PITCH 的目标值及线性斜率，作用于同 ID 所有活动 voice。STOP 的独立 fade factor 归零后 key-off，循环 ID 管理表在请求时即移除。`LinearRamp` 可逐原音频 update 推进。cue 延时由原 cue scheduler 负责，不能把 transition 当作触发延时。

| 原参数 | 明确映射 |
|---|---|
| volume | `float32(raw / 100)`；最终 `clamp(trunc(base_volume × volume_factor × stop_fade_factor),0,16383)` |
| pan | `float32(raw × float32(.01))`，再 `clamp(trunc(pan × 8)+8,0,16)` |
| SE_PLAY pitch | 入队但 `0x13FA20–0x13FA90` 不读取，实际初始 factor 为 1；不得擅自应用 |
| CHANGE_PITCH | 使用 `legacy_pitch_factor()`：每 100 原单位一旧式档，正负倍率分别 1.0833 / .91667；每 1200 单位精确 ×2 / ×.5，并按原常量计算小数档。它不是十二平均律 cents |
| 最终 pitch | `clamp(trunc(base_pitch × factor),0,4095)`；WAV 播放速率相对原 base pitch 比例变化 |
| transition | 音频 update 数；函数先除60，再由库乘60恢复步数，线性推进；名义秒数 `raw/60`，实际原时钟仍依赖视频同步 |
| completion | PLAY 正 transition 时等待 `transition+1` 次同步；STOP/CHANGE 非零 completion 时同样等待 `transition+1` |

`0x1B0338→0x14F0F0` 等待同步后调用 `0x1B0340→0x1B0CB8→0x1D06F4→0x1D2F34`，每次更新启动倒数、参数斜率及增益。现代后端应使用 VM 明确的时钟，保存推进计数；不要把60写死为原硬件所有情况下的精确墙钟频率。

另有原队列优化：若即时 SE_PLAY 后尚排队同 ID 的“音量改为0且 transition 非零”，`0x13F750` 将 PLAY 初始音量改0。`queued_play_volume()`保留这一规则。原线程、优先级分配、10个逻辑 voice 配额及8个循环 ID 配额仍由更高层调度恢复，不在参数函数里伪造。

## 532019 的存储双流与实际播放

本盘记录的 Flag `0x80` 均未置位。原 EE `0x1D250C–0x1D2528` 仅在该位置位时选择第二条流并清零延迟；否则两个 voice 都从第一条流开始，Delay 为记录 `+54/+55`。这解释了双流素材为何不能直接用保全用 stereo WAV 替代。SSDV 模块不改写 bank，它接收 EE 已选择的两个地址。

IOP 独立 `ssdvStereoFlag` 的原初始化为1，EE初始化也设1；现代后端显式传输出模式。立体声模式中，原表为17对整数，**表内顺序 R,L**。双 voice 同批 `SetChannel=3` 时用完整系数；分批启动时 voice0 的 R 系数先整数除8，voice1 的 L 系数先整数除8，然后各自 `volume_register × coefficient /16` 截断。原 mono 输出模式则每个 voice 的 L、R 都是 `trunc(volume_register×8/10)`。平台混音时应保留这个整数矩阵及截断顺序。

| 音效与参数 | 选择流 | key-on update（从1开始） | 目标寄存器矩阵，行=voice，列=L/R |
|---|---|---|---|
| 537002，volume80，pan0 | `[0,0]` | `[1,15]` | `[[9600,800],[800,9600]]` |
| 532019，volume15，pan-30 | `[0,0]` | `[1,3]` | `[[1950,150],[150,1500]]` |
| 101039，volume100，pan0（参数示例） | `[0,0]` | `[1,1]` | `[[12000,12000],[12000,12000]]` |

前两项相对启动差为14和2次 update。所有原始流仍完整保留；实际原版混音录音对比与原生听测尚未完成。`docs/SE_BANK.md` 的早期“双流路由待恢复”由本契约的源代码分析补齐，并不将离线素材改称运行录音。

每个输出寄存器除16384得到进入后续 ADSR/混响/core master 之前的线性增益。这来自 [PCSX2 的 RegSet 寄存器移位](https://github.com/PCSX2/pcsx2/blob/master/pcsx2/SPU2/ADSR.cpp) 与 [Mixer 的固定点音量乘法](https://github.com/PCSX2/pcsx2/blob/master/pcsx2/SPU2/Mixer.cpp)。原 CVT.W.S 的向零转换也核对了 [PCSX2 FPU 实现](https://github.com/PCSX2/pcsx2/blob/master/pcsx2/FPU.cpp)。本项目没有复制这些解码器源码。

## MMV

`MmvPlayback(loop_tail)` 对应 `0x198158` 线程。开始 member0；结束后将 index0改1；此后不再递增。循环位开时反复播放 member1；关闭时第二段结束进入完成／排空等待。显式 stop 终止，不重启。

`pr5011m.mmv`：**member0近水90帧一次 → member1海岛90帧循环**。依据不是文件名或画面猜测：MMV 类型表 `+36=1` 传至依赖 flags、manager+84、`13F038`、`195150→195378→197C10`，最终设置 decoder+512 的 bit0。当前 scope 是原始两成员 MMV，不把32条目录容量误当作任意长度顺播支持。

## 原逻辑与平台适配

必须保留原始 ID、源流选择、voice 启动差、循环样本点、开始停止顺序、重复循环抑制、增益矩阵、原参数单位和 transition 目标。原字幕/译文不影响原声音频内容。

允许现代后端使用设备重采样和输出格式、明确标注的用户总音量、控制步间平滑插值，以及首遍 PCM 循环代替 SPU2 预测器历史的逐圈重解码。ADSR／混响可先采用明确说明的近似；这些属于音色／输出适配，不能借此改变声道选择、淡入淡出时间或跳过音效。当前合同给出的是 per-voice 干声增益边界，不宣称完整原硬件混音位级一致。后端需保存自己的有效参数、时钟及采样位置，使恢复可复核。

```powershell
python tools/audio_media_contract.py
python -m unittest discover -s tests -p test_audio_media_contract.py -v
```
