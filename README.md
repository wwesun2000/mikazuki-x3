# Mikazuki X3

**English** · An unofficial native Windows port of *Kamaitachi no Yoru ×3: Mikazuki-jima Jiken no Shinsō*. The player reads artwork, Japanese voices and story resources directly from your own Japanese PS2 disc image. The port runs recovered game logic in C++ and provides mouse and keyboard controls, saves, fullscreen, Scale2x, scanlines and Japanese, Chinese and English text.

**日本語** · 『かまいたちの夜×3 三日月島事件の真相』の非公式 Windows ネイティブ移植です。プレイにはご自身で用意した日本版 PS2 の原盤イメージが必要です。原作の音声と画像を使用し、日本語・中国語・英語のテキストを切り替えられます。

**中文** · 《镰鼬之夜×3 三日月岛事件的真相》的非官方 Windows 原生移植。游戏资源从自备日版 PS2 原盘镜像读取，保留日语原声和原图，可切换日中英文字。

## What you can build

This repository contains the host runtime and game logic, the Windows UI, ISO and FAD tools, generators, Ghidra scripts and tests. Run the Python disc tools with Python 3.13. Their isolated tests create small synthetic fixtures.

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

This project is for technical exchange and noncommercial use. Game rights belong to their respective holders. Third-party tools retain their own licenses. The public tree carries project source and tooling. Full game scripts, translation manuscripts, disc images, BIOS, personal saves and prebuilt player binaries stay outside it. Some technical documents reference evidence generated only in a private working tree.

**wwesun2000** initiated the project, set its direction and provided playtesting feedback. **OpenAI Codex** worked on reverse engineering, native implementation, Chinese translation and verification. **Claude** contributed technical consultation and English translation. **Gemini** contributed Chinese copyediting and proofreading.
