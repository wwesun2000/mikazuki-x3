# itch.io release operations

Target: `wwesun2000/mikazuki-x3:windows`. Expected page: https://wwesun2000.itch.io/mikazuki-x3 (configuration target, not evidence of an existing publication).

## Verified draft deployment (2026-11-14)

The itch project exists as ID `5357914` and must remain **Draft**. Environment
`itch-production` permits `main` and `v*`. The existing repository Secret
`BUTLER_API_KEY` is inherited by these jobs; its value was not retrieved.
Read-only credential run `43562718737` passed for `wwesun2000` and this draft.
The YouTube video, original promotional cover and bilingual usage page are saved.

For this draft, use `itch-draft-upload.yml`: upload the locally verified ZIP to
a **draft GitHub Release**, then dispatch on `main` with its numeric asset ID and
the SHA256 from the package audit. The job uses the read-only GitHub job token to
fetch that asset, verifies the exact 16-file allowlist, all per-file checksums,
decoder and source identity, and the pinned Butler binary. It verifies the itch
account/project is still unpublished before and after pushing `:windows`.
It does not change visibility or publish the GitHub draft. This is the usable
update route without uploading private compile inputs to a remote build service.

`itch-release.yml` retains the requested Windows source-build/tag/Release route.
It additionally needs a private compile-input hosting URL and reviewed bundle
hash; those are **not configured**. It fails closed. `ITCH_RELEASE_REVIEWED=false`
keeps automatic public release disabled. Do not fabricate rights clearance or
upload the original disc to make that gate pass. Draft staging and third-party
license checks are not permission from the original game rights holders.

## Source-build route and remaining conditions

The workflow builds the native player, not an emulator or a downloaded replacement EXE. Public source currently requires the private files listed with SHA256 fingerprints in `local-build-inputs.json`; a clean public clone alone cannot build. Do not upload the ISO or BIOS to CI, GitHub or itch. The private build bundle must contain only those generated inputs and the explicit runtime/legal files below. Their redistribution rights still need review; absence of ISO is not full copyright clearance.

The itch decoder is a separately built, minimal FFmpeg 7.1 LGPL 2.1-or-later executable,
not the historical Gyan GPL essentials binary. Run `43563580316` builds it from
checksum-pinned, unmodified FFmpeg source without GPL/nonfree/external codec libraries.
Its exact source archive, complete build script, configure log, DLL imports and
MinGW/GCC runtime notices ship in the ZIP. Eight original-disc samples (IPU,
Vorbis, MPEG elementary/program streams) match the historical decoder byte-for-byte.
This is sample equivalence, not full-game regression. The player's old decoder
identity remains accepted for existing installations; only the new identity is
eligible for the itch packager. Project noncommercial conditions do not restrict
third-party licenses. The project is source-available, not OSI-open-source under
its noncommercial policy. Original-game/translation rights are a separate issue.

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

Protected ZIP layout: all `private_inputs` paths exactly as recorded in `local-build-inputs.json`, plus `runtime/ffmpeg.exe`, `legal/ffmpeg-7.1.tar.xz` and every legal text listed in `tools/package_itch.py::LEGAL_TEXTS`. No directory entries or extra files. The decoder and FFmpeg source are hash-pinned. License review remains a maintainer responsibility; checksums do not establish copyright permission.

The input loader verifies the entire ZIP hash, rejects extra/duplicate entries, and only writes exact reviewed paths. The existing build verifies each generated input. No runtime input bundle is retained as a public Actions artifact.

## Pipeline

1. Select either Release or tag triggering (not both) to avoid duplicate pushes.
2. Download checksum-pinned compiler and butler; download and verify protected inputs.
3. Compile `KamaitachiX3.exe` and native `MikazukiX3.exe` on Windows.
4. `tools/package_itch.py` copies exactly three AMD64 executables, launch manifest, bilingual instructions, nine legal/build texts and the exact FFmpeg source archive, then adds SHA256SUMS (16 files total). It never copies a workspace recursively. ISO/BIN/IMG/BIOS, media, caches, credentials and saves are not eligible paths.
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
