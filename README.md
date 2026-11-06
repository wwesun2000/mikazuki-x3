# Mikazuki X3

**English** · An unofficial native Windows port of *Kamaitachi no Yoru ×3: Mikazuki-jima Jiken no Shinsō*. The player reads artwork, Japanese voices and story resources directly from your own Japanese PS2 disc image. The port runs recovered game logic in C++ and provides mouse and keyboard controls, saves, fullscreen, Scale2x, scanlines and Japanese, Chinese and English text.

**日本語** · 『かまいたちの夜×3 三日月島事件の真相』の非公式 Windows ネイティブ移植です。プレイにはご自身で用意した日本版 PS2 の原盤イメージが必要です。原作の音声と画像を使用し、日本語・中国語・英語のテキストを切り替えられます。

**中文** · 《镰鼬之夜×3 三日月岛事件的真相》的非官方 Windows 原生移植。游戏资源从自备日版 PS2 原盘镜像读取，保留日语原声和原图，可切换日中英文字。

## Downloads

Ready-to-run packages are provided under [GitHub Releases](https://github.com/wwesun2000/mikazuki-x3/releases).

- **Windows:** extract the portable ZIP and launch `MikazukiX3.exe`. A command-script launcher is not required.
- **Android 0.1.1 test:** install the ARM64 APK on Android 8.0 or newer, then select your own ISO using the system file picker. Landscape touch controls, a centered scene, moonlit side menus, direct branch selection, Japanese/Chinese/English text, saves, scanlines and screenshot location codes are included. No virtual D-pad or controller buttons are shown. See the [Android test guide](docs/ANDROID_TEST.md).
- **中文：** Windows 压缩包解压后双击 EXE；安卓直接安装 APK，触屏操作，画面居中、两侧菜单，仅保留扫描线滤镜。两个版本均需自备日版原盘 ISO，不需要 BIOS。安卓目前为测试版。
- **日本語：** Windows は ZIP を展開して EXE を実行、Android は ARM64 APK をインストールしてください。日本版 ISO は各自で用意してください。Android はタッチ操作・走査線フィルター対応のテスト版です。

Packages contain no ISO, BIOS or personal save data. Android has been checked in an emulator, including ARM64 execution under translation; physical iQOO Z9 Turbo, other devices and 16KB-page execution still need real-device feedback. Static 16KB ELF alignment checks alone are not a claim of device validation.

## What you can build

This repository contains the host runtime and game logic, the Windows and Android UIs, ISO and FAD tools, generators, Ghidra scripts and tests. Run the Python disc tools with Python 3.13. Their isolated tests create small synthetic fixtures.

```console
python -B -m unittest discover -s tests -p test_iso9660.py
python -B -m unittest discover -s tests -p test_fad.py
python tools/iso9660.py --help
```

The Windows build additionally needs the local inputs listed by path and SHA-256 in [local-build-inputs.json](local-build-inputs.json). These include generated C++ headers, resource catalogues and the compiled localization tables. The research generators have prerequisites such as local PS2Recomp/Ghidra exports and reviewed text inputs. A retail disc alone does not currently reproduce the edited Chinese and English tables. A fresh clone therefore cannot yet build the complete trilingual player from an ISO alone.

To use an existing compatible local input tree, point the build helper to its root and your own Zig 0.15.2 installation. It validates the inputs, builds in a private directory and installs the executable under `local/pc-core/player/`. The public window source omits the internal story-fixture verification commands.

```console
python tools/build_public_player.py --inputs "<local input tree>" --check-only
python tools/build_public_player.py --inputs "<local input tree>" --zig "<path to zig.exe>"
```

At runtime, place your locally obtained `ffmpeg-win-x86_64-v7.1.exe` under `local/dependencies/imageio_ffmpeg/binaries/`. Run `Play-PC.cmd` and select your own ISO. Back up the complete `local/pc-core/player/saves/` folder to preserve both session and card records.

## Scope and contributions

This project is for technical exchange and noncommercial use. Game rights belong to their respective holders. Third-party tools retain their own licenses. The public tree carries project source and tooling; prebuilt players are Release attachments. Full game scripts, translation manuscripts, disc images, BIOS and personal saves are not published as repository files. Some technical documents reference evidence generated only in a private working tree. The Android build shares the existing local generated-input requirements described above; public source alone does not regenerate the reviewed translation tables.

**wwesun2000** initiated the project, set its direction and provided playtesting feedback. **OpenAI Codex** worked on reverse engineering, native implementation, Chinese translation and verification. **Claude** contributed technical consultation and English translation. **Gemini** contributed Chinese copyediting and proofreading.
