$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$toolchainRoot = Join-Path $projectRoot 'local\dependencies\ps2recomp\_evaluation'
$zig = Join-Path $toolchainRoot 'toolchain\zig-x86_64-windows-0.15.2\zig.exe'
$env:ZIG_GLOBAL_CACHE_DIR = Join-Path $toolchainRoot 'zig-global-cache'
$env:ZIG_LOCAL_CACHE_DIR = Join-Path $projectRoot 'local\pc-core\media-zig-local-cache'
$outputRoot = Join-Path $projectRoot 'local\pc-core'
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
$sources = @(Get-ChildItem -LiteralPath (Join-Path $projectRoot 'port\core') -Filter '*.cpp' | ForEach-Object FullName) + @(
    (Join-Path $projectRoot 'port\platform\windows\raster_loader.cpp'),
    (Join-Path $projectRoot 'port\platform\windows\source_codec.cpp'),
    (Join-Path $projectRoot 'port\platform\windows\project_media.cpp'),
    (Join-Path $projectRoot 'port\platform\windows\project_movie.cpp'),
    (Join-Path $projectRoot 'port\platform\windows\project_font.cpp'),
    (Join-Path $projectRoot 'port\platform\text_layer.cpp'),
    (Join-Path $projectRoot 'port\tests\story_frame_scenarios.cpp'),
    (Join-Path $projectRoot 'port\tools\media_state_probe.cpp')
)
$tracked = @($sources) + @(Get-ChildItem -LiteralPath (Join-Path $projectRoot 'port\core') -Filter '*.hpp' | ForEach-Object FullName) + @(
    (Join-Path $projectRoot 'port\platform\windows\raster_loader.hpp'),
    (Join-Path $projectRoot 'port\platform\windows\source_codec.hpp'),
    (Join-Path $projectRoot 'port\platform\original_media_catalog.hpp'),
    (Join-Path $projectRoot 'port\platform\windows\project_media.hpp'),
    (Join-Path $projectRoot 'port\platform\windows\project_movie.hpp'),
    (Join-Path $projectRoot 'port\platform\movie_catalog.hpp'),
    (Join-Path $projectRoot 'port\platform\movie_stream_index.hpp'),
    (Join-Path $projectRoot 'port\platform\windows\project_font.hpp'),
    (Join-Path $projectRoot 'port\platform\raster_frame.hpp'),
    (Join-Path $projectRoot 'port\platform\sab_layer.hpp'),
    (Join-Path $projectRoot 'port\platform\gs_blend.hpp'),
    (Join-Path $projectRoot 'port\platform\text_layer.hpp'),
    (Join-Path $projectRoot 'port\tests\story_frame_scenarios.hpp'),
    (Join-Path $projectRoot 'port\platform\image_catalog.hpp')
)
. (Join-Path $PSScriptRoot 'freeze_port_sources.ps1')
$frozen=Get-PortSourceSnapshot $projectRoot (Join-Path $outputRoot 'media-state') $tracked
$inputs=@($sources | ForEach-Object {Join-Path $frozen.Directory $_.Substring($projectRoot.Length+1)})
$outputExe = Join-Path $frozen.Directory 'media_state_probe.exe'
& $zig c++ -std=c++20 -target x86_64-windows-gnu -O2 -g -fno-fast-math -ffp-contract=off -municode @inputs -lole32 -lwindowscodecs -luuid -lbcrypt -o $outputExe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$record = [ordered]@{
    built_utc = [DateTime]::UtcNow.ToString('o')
    compiler = $zig
    compiler_sha256 = (Get-FileHash -LiteralPath $zig -Algorithm SHA256).Hash.ToLowerInvariant()
    sources = $frozen.Frozen
    workspace_sources = $frozen.Originals
    flags = @('-std=c++20','-target','x86_64-windows-gnu','-O2','-g','-fno-fast-math','-ffp-contract=off','-municode','-lole32','-lwindowscodecs','-luuid','-lbcrypt')
    output = $outputExe
    output_sha256 = (Get-FileHash -LiteralPath $outputExe -Algorithm SHA256).Hash.ToLowerInvariant()
}
Copy-Item -LiteralPath $outputExe -Destination (Join-Path $outputRoot 'media_state_probe.exe') -Force
[IO.File]::WriteAllText((Join-Path $frozen.Directory 'build.json'), ($record | ConvertTo-Json -Depth 5))
[IO.File]::WriteAllText((Join-Path $outputRoot 'media_state_probe.build.json'), ($record | ConvertTo-Json -Depth 5))
Get-FileHash -LiteralPath $outputExe -Algorithm SHA256 | Format-List Path,Hash
