# Mikazuki X3 — Windows usage / Windows 使用说明

## 中文

**本下载不包含游戏 ISO、BIN、IMG、PS2 BIOS 或从原盘提取的音视频文件。请自行准备合法取得的原版光盘镜像；不要向本项目、GitHub、itch.io 或问题反馈区上传镜像或 BIOS。**

当前支持原版日版《镰鼬之夜 ×3》光盘镜像（SLPM-66452）。不宣称支持美版、欧版、修改版或其他游戏镜像。此原生播放器不需要 BIOS 或模拟器。

1. 将整个 Windows ZIP 解压到可写目录，保留所有子目录；不要直接在压缩包内运行。
2. 双击根目录的 **MikazukiX3.exe**，在文件选择器中选择自己的 `.iso`。也可以将 ISO 文件拖到该 EXE 图标上启动。这里指文件图标拖放，不承诺游戏窗口内拖放。
3. 选择篇章和“新游戏”。按 **F1** 打开设置，选择文字语言和滤镜。鼠标点击菜单及剧情选项；Enter 确认，Backspace 返回。按 **F11** 切换全屏。

程序直接读取本地 ISO 中的原图、原声和游戏数据，不需要上传镜像，也不要求把光盘全部解包。游玩时请保留 ISO；移动或删除镜像后需要重新选择有效位置。中英翻译改变文字，不替换原声及原图中的日文。

在原游戏允许的位置通过游戏菜单保存。更新或迁移前，备份整个 `local/pc-core/player/saves/` 文件夹（包含 `memory-card/`）。不要用新版本覆盖自己的存档。

按 **F12** 保存截图，反馈时保留完整画面、定位码和文件名，并描述此前操作；不要附带 ISO、BIOS 或提取素材。截图目录为 `captures/screenshots/`。

本程序仅供非商业技术交流，与原权利人无隶属或背书关系。原作及素材权利归相应权利人所有。此说明不构成权利授权；翻译、恢复代码和第三方组件的发布条件须分别审核。

## English

**This download does not include a game ISO, BIN, IMG, PS2 BIOS, or audio/video files extracted from the original disc. Supply your own lawfully obtained disc image. Do not upload images or BIOS files to this project, GitHub, itch.io, or issue reports.**

The supported disc is the original Japanese release of Kamaitachi no Yoru ×3, **SLPM-66452**. US/EU editions, modified images and other games are not advertised as supported. No PS2 BIOS or emulator is required.

1. Extract the complete Windows ZIP to a writable folder, keeping its subfolders.
2. Run **MikazukiX3.exe** and select your local `.iso` in the file picker. Alternatively, drop the ISO onto the EXE file icon. This does not imply drag-and-drop inside the game window.
3. Select a story and New Game. Press **F1** for language and filter settings. Click menus and story choices with the mouse; Enter confirms and Backspace goes back. **F11** toggles fullscreen.

The player reads original images, voices and game data directly from your local ISO. No image upload or complete disc extraction is required. Keep the ISO available while playing; select it again if you move it. Translation changes displayed text, leaving original audio and text embedded in images unchanged.

Save through the game menu where permitted. Before updating or moving the installation, back up the entire `local/pc-core/player/saves/` directory, including `memory-card/`. Preserve your existing saves when updating.

Press **F12** to capture a screenshot. Include the complete screenshot, its diagnostic code and filename, and recent actions when reporting a problem. Screenshots are saved under `captures/screenshots/`. Do not attach disc images, BIOS files or extracted assets.

For noncommercial technical exchange. This is an independent project, not affiliated with or endorsed by the original rights holders. Original game and asset rights belong to their respective owners. This notice grants no rights; distribution conditions for translations, recovered code and third-party components require separate review.

Source: https://github.com/wwesun2000/mikazuki-x3

## Third-party software / 第三方软件

This package invokes FFmpeg 7.1 as a separate program, licensed under LGPL 2.1 or later. Its complete corresponding source, build script, configuration and notices are in `licenses/`. The project’s noncommercial notice does not restrict rights granted by FFmpeg or MinGW/GCC licenses. This is source-available project code; the noncommercial condition is not an OSI-approved open-source license and grants no rights in the original game.

本包将 FFmpeg 7.1 作为独立程序调用，适用 LGPL 2.1 或更新版本；完整对应源码、构建脚本、配置与声明位于 `licenses/`。本项目的非商业说明不限制 FFmpeg、MinGW/GCC 许可证授予的权利。项目源码公开，但非商业条件不属于 OSI 批准的开源许可证，也不授予原作权利。
