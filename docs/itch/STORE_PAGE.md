# Store configuration (not part of the public description)

- Account / slug: `wwesun2000/mikazuki-x3`
- Title: **Mikazuki X3 — Native Windows Player**
- Kind: Downloadable; platform: Windows; architecture requirement: x86-64 (AMD64).
- Classification: use **Game** for this playable native port. Use **Tool** only if distributing a separate utility rather than the playable port. Do not misclassify to avoid review. If the current dashboard provides a suitable mod category, describe accurately; do not assume a `Game mod` option exists.
- Release status: In development / preview, until full route acceptance is documented.
- Pricing: recommended **No payments** under the existing noncommercial project policy. `$0 or donate` is an optional owner decision after rights review, not a copyright safeguard.
- Candidate tags (select available, accurate ones): `visual-novel`, `interactive-fiction`, `mystery`, `horror`, `multiple-endings`, `translation`, `mouse-only`. Do not claim accessibility or complete route coverage without testing.
- Short description: **An independent native Windows player with Chinese and English text, mouse controls and display filters. Requires your own Japanese game-disc ISO.**
- Content advisory: fictional murder, horror and mature themes; not an official age rating.
- AI disclosure: disclose AI-assisted reverse engineering, programming, translation and proofreading, and AI-generated promotional art wherever applicable. Do not label the original game's art AI-generated.
- Use original project UI captures for the three illustrated steps below; crop out personal paths. Insert hosted image URLs before publication; the text guide works without images. Do not upload raw disc assets.

---

# Mikazuki X3 — Native Windows Player

Revisit a branching Japanese mystery through an independent native Windows player. **Bring your own original Japanese game-disc ISO (SLPM-66452). No game image or BIOS is included or required to be uploaded.**

## Features

- A redesigned Windows interface with mouse-clickable menus and story choices, plus keyboard controls.
- Japanese, Chinese and English text selection. Original voices and artwork remain unchanged; Japanese text embedded in images is retained.
- Fullscreen, conventional scaling filters and an optional scanline filter. No AI upscaling hardware is required.
- Local progress saves and screenshot diagnostic codes to help investigate reports.

This is a preview release. Translation and behavior reports are welcome; it is not a claim that every branch has completed end-to-end acceptance testing.

## Get started in three steps

**1 — Prepare your disc.** Obtain your own lawful ISO of the supported Japanese release, SLPM-66452. Other regions and modified images are not advertised as supported. No PS2 BIOS or emulator is needed.

**2 — Extract and launch.** Extract the entire download to a writable folder. Run **MikazukiX3.exe** and choose the ISO in the file picker. You may also drop the ISO onto the EXE icon. Keep the ISO available: the player reads it locally rather than bundling or downloading the game's assets.

**3 — Choose your settings and play.** Press **F1** for language and display settings. Click menus and choices; Enter confirms, Backspace goes back. **F11** toggles fullscreen. The player follows the original game's permitted save points.

Before updating, back up the complete `local/pc-core/player/saves/` directory, including `memory-card/`. Press **F12** for a screenshot when reporting an issue. Preserve the diagnostic code and describe your recent actions; never attach an ISO, BIOS or extracted disc assets.

## Source and integrity

[View source and report issues on GitHub](https://github.com/wwesun2000/mikazuki-x3)

[![GitHub repository](https://img.shields.io/badge/GitHub-mikazuki--x3-181717?logo=github)](https://github.com/wwesun2000/mikazuki-x3)

The source repository documents the build and its locally generated input requirements. Release builds include SHA-256 file checksums; compare the ZIP against its accompanying `.sha256` file. Checksums detect changes, but do not replace code signing or guarantee antivirus approval. The game image is read from your computer, not uploaded by the import flow. Local settings, saves and diagnostic captures are written for play and support.

## Independent project and rights notice

This is an independent, unofficial native player and localization project, not affiliated with or endorsed by the original developer or publisher. Downloads contain no original disc image, PS2 BIOS, or separately extracted original audio/video assets. Supply your own supported disc image.

The original game, characters, artwork, audio and associated intellectual property belong to their respective rights holders. This project includes localization text and recovered program behavior; it does not claim ownership of the underlying work or grant rights to it. Source availability does not override third-party licenses. Project-authored material is presented for noncommercial technical exchange; third-party components retain their own license terms. Rights holders can contact the maintainer through the linked repository.

## Credits

**wwesun2000:** project direction, testing and feedback. **OpenAI Codex:** reverse engineering, native implementation, Chinese translation, integration and testing. **Claude:** technical consultation and English translation assistance. **Gemini:** Chinese proofreading assistance. Original game credits remain with the original creators.

---

# Mikazuki X3 — Windows 原生播放器

以现代 Windows 操作方式体验分支推理故事。**请自行准备原版日版光盘镜像（SLPM-66452）。下载不包含 ISO、BIOS，也不要求上传镜像。**

## 功能亮点

- 重构 Windows 界面，菜单与剧情选项支持鼠标点击，同时保留键盘操作。
- 支持日文、中文和英文文字切换；原声、原图及图片内的日文保持原样。
- 全屏、常规缩放滤镜和扫描线滤镜，无需 AI 超分专用硬件。
- 本地保存进度，截图附定位码，便于反馈问题。

目前为预览版本，欢迎反馈翻译和行为问题；不代表所有分支均已完成全流程验收。

## 三步开始

**第一步：准备镜像。** 自行合法取得受支持的日版 SLPM-66452 ISO。暂不宣称支持其他地区或修改版镜像，不需要 PS2 BIOS 或模拟器。

**第二步：解压启动。** 完整解压到可写目录，双击 **MikazukiX3.exe**，在文件选择器中选择 ISO；也可把 ISO 拖到 EXE 文件图标上。程序直接读取本地镜像，不下载或附带原盘素材，游玩期间请保留镜像。

**第三步：设置并游玩。** 按 **F1** 选择文字语言与画面滤镜，鼠标点击菜单和选项，Enter 确认，Backspace 返回，**F11** 切换全屏。在原游戏允许的位置保存进度。

更新前备份整个 `local/pc-core/player/saves/`（含 `memory-card/`）。遇到问题按 **F12** 截图，保留定位码并说明最近操作；不要提交 ISO、BIOS 或提取素材。

## 源码、安全与权利说明

[GitHub 源码及问题反馈](https://github.com/wwesun2000/mikazuki-x3)。仓库说明了构建方法及本地生成输入要求。发布包提供 SHA-256 校验清单；校验码用于检测文件变化，不代表数字签名或杀毒软件认证。导入过程读取本机 ISO，不上传镜像；设置、存档和截图保存在本地。

本项目为独立非官方原生播放器与本地化项目，未获原开发商或发行商背书。下载不含原盘镜像、PS2 BIOS 或单独提取的原盘音视频。原作、角色、美术、音频及相关知识产权归相应权利人所有。项目包含本地化文字及恢复的程序行为，不声称拥有原作权利。项目自有内容用于非商业技术交流，第三方组件适用各自许可证；源码公开及免责声明均不构成原作授权。权利人可通过上述仓库联系维护者。

**贡献：**wwesun2000 发起并主导项目、试玩反馈；OpenAI Codex 负责逆向、原生实现、中文翻译及集成验证；Claude 协助技术咨询与英文翻译；Gemini 协助中文校对。原游戏创作贡献归原制作团队。
