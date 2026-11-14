# itch.io release operations

Target: `wwesun2000/mikazuki-x3:windows`. Expected page: https://wwesun2000.itch.io/mikazuki-x3 (configuration target, not evidence of an existing publication).

## Scope and current blockers

The workflow builds the native player, not an emulator or a downloaded replacement EXE. Public source currently requires the private files listed with SHA256 fingerprints in `local-build-inputs.json`; a clean public clone alone cannot build. Do not upload the ISO or BIOS to CI, GitHub or itch. The private build bundle must contain only those generated inputs and the four explicit runtime/legal files below. Their redistribution rights still need review; absence of ISO is not full copyright clearance.

The current decoder is Gyan's FFmpeg 7.1 essentials build, configured with `--enable-gpl --enable-version3`. The imageio wrapper's license does not license this decoder. Complete the decoder's corresponding-source/license obligations and review translations/recovered-code distribution before enabling `ITCH_RELEASE_REVIEWED`. A generic source homepage alone is not proof of corresponding-source availability. Existing package auditing is not a legal certification.

## One-time setup

Create the itch project under the confirmed account and slug. Keep visibility draft until the package and page are reviewed. Create a GitHub environment named `itch-production` and configure:

| Name | Kind | Value |
| --- | --- | --- |
| `BUTLER_API_KEY` | environment secret | itch API key; never commit or paste into logs |
| `ITCH_INPUTS_URL` | environment secret | protected HTTPS download URL for a reviewed input ZIP; expiry must cover the run |
| `ITCH_INPUTS_SHA256` | variable | SHA256 of that exact ZIP |
| `ITCH_ZIG_SHA256` | variable | independently checked SHA256 of official Zig 0.15.2 Windows x86-64 ZIP |
| `ITCH_BUTLER_VERSION` | variable | exact stable version, e.g. digits.digits.digits; not LATEST |
| `ITCH_BUTLER_SHA256` | variable | independently checked SHA256 of that exact Windows AMD64 ZIP |
| `ITCH_RELEASE_REVIEWED` | variable | `true` only after the release-specific rights/license/input review |
| `ITCH_TRIGGER` | repository variable | default empty: published non-prerelease Release; `tag`: push of `v*` instead |

Do not supply secrets through chat. Configure environment branch/tag restrictions so untrusted branches cannot access release credentials. Actions tokens have read-only repository permissions. No pull-request trigger is present. Manual dispatch is available for controlled retries; do not retry an already successful push without checking itch build history.

Protected ZIP layout: all `private_inputs` paths exactly as recorded in `local-build-inputs.json`, plus `runtime/ffmpeg.exe`, `legal/FFmpeg-LICENSE.txt`, `legal/FFmpeg-SOURCE.txt`, `legal/THIRD-PARTY-NOTICES.txt`. No directory entries or extra files. License text must be the actual applicable license; SOURCE must identify the exact binary, corresponding source/build materials and how recipients obtain them in compliance with its license. A maintainer must review these texts; the packager only checks presence/encoding, not legal sufficiency.

The input loader verifies the entire ZIP hash, rejects extra/duplicate entries, and only writes exact reviewed paths. The existing build verifies each generated input. No runtime input bundle is retained as a public Actions artifact.

## Pipeline

1. Select either Release or tag triggering (not both) to avoid duplicate pushes.
2. Download checksum-pinned compiler and butler; download and verify protected inputs.
3. Compile `KamaitachiX3.exe` and native `MikazukiX3.exe` on Windows.
4. `tools/package_itch.py` copies exactly three AMD64 executables, launch manifest, bilingual instructions and three legal texts into a new isolated directory. It never copies a workspace recursively. ISO/BIN/IMG/BIOS, media, caches, credentials and saves are not eligible paths.
5. Generate per-file SHA256 checksums, ZIP digest and audit report; reopen and verify the ZIP.
6. Run `butler validate --platform windows --arch amd64`, retain only the ZIP/digest/audit as an Actions artifact, then push only `build/MikazukiX3-Windows`.

The official `.itch.toml` action uses `platform = "windows"`; no undocumented `arch` key is invented. AMD64 is enforced by PE machine checks and butler validation. Butler provides incremental downloads, not live patching a running game. Before updating, close the game and back up saves. Verify save preservation in the itch app before recommending automatic updates broadly.

## Local package command

```powershell
python -B tools/package_itch.py --player local/pc-core/player/KamaitachiX3.exe --launcher local/MikazukiX3.exe --decoder local/itch-inputs/runtime/ffmpeg.exe --legal local/itch-inputs/legal --output build/MikazukiX3-Windows
```

Use a new output path on retries; no recursive cleanup or overwrite of a live installation is performed. Never run `butler push .` or push the project root. Hash manifests improve integrity checking, not Defender reputation or signing status; never advise disabling antivirus.

## First-run behavior and acceptance

Existing player opens a bilingual ISO file picker, accepts an ISO passed through the EXE icon, remembers its path, and reads resources directly. The current implementation validates disc/resource structures and relevant SHA256 fingerprints; it does NOT provide a background whole-disc SHA1/MD5 progress UI. US/EU support and automatic full-disc extraction are not implemented and are not advertised. Further first-run UX changes need a separate native build and test, not fictional store claims.

Before public visibility: test picker cancellation, invalid/wrong-region image errors, a valid Japanese image, relaunch after moving the ISO, and launch via the itch Desktop App; verify read/save/language/filter functions and updater save preservation. Record actual results and binary hashes. This configuration has not itself demonstrated those live itch tests or a successful CI publish.

References: [manifest actions](https://itch.io/docs/itch/integrating/manifest-actions.html), [butler installation](https://itch.io/docs/butler/installing.html), [butler pushing](https://itch.io/docs/butler/pushing.html), [platform terms](https://itch.io/docs/legal/terms). Classification and disclaimers do not bypass rights requirements.
