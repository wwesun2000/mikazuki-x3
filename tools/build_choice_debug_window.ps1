$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$toolchain = Join-Path $projectRoot 'local/dependencies/ps2recomp/_evaluation'
$zig = Join-Path $toolchain 'toolchain/zig-x86_64-windows-0.15.2/zig.exe'
$env:ZIG_GLOBAL_CACHE_DIR = Join-Path $toolchain 'zig-global-cache'
$env:ZIG_LOCAL_CACHE_DIR = Join-Path $projectRoot 'local/pc-core/choice-debug/zig-cache'
$destination = Join-Path $projectRoot 'local/pc-core/choice-debug'
New-Item -ItemType Directory -Path $destination -Force | Out-Null
$localeGenerator = Join-Path $PSScriptRoot 'generate_choice_locales.py'
$localeData = Join-Path $destination 'choice_locale_data.inc'
& (Join-Path $PSScriptRoot 'python.ps1') -B $localeGenerator $localeData
if ($LASTEXITCODE -ne 0) { throw 'Could not bind source choice translations' }
$sources = @(Get-ChildItem -LiteralPath (Join-Path $projectRoot 'port/core') -Filter '*.cpp' -File | Select-Object -ExpandProperty FullName)
$sources += @('port/platform/text_layer.cpp','port/platform/windows/raster_loader.cpp',
    'port/platform/windows/window_drawing.cpp','port/platform/windows/choice_locale.cpp',
    'port/platform/windows/choice_debug_window.cpp') | ForEach-Object { Join-Path $projectRoot $_ }
$headers = @('port/core','port/platform','port/platform/windows') | ForEach-Object {
    Get-ChildItem -LiteralPath (Join-Path $projectRoot $_) -Filter '*.hpp' -File | Select-Object -ExpandProperty FullName
}
$inputs = @($sources) + @($headers) + @($localeGenerator, $localeData)
$hashes = [ordered]@{}
foreach ($item in $inputs) { $hashes[$item] = (Get-FileHash -LiteralPath $item).Hash.ToLowerInvariant() }
$flags = @('-std=c++20','-target','x86_64-windows-gnu','-O2','-g','-I', $destination,'-fno-fast-math','-ffp-contract=off',
    '-DUNICODE','-D_UNICODE','-municode','-Wl,--subsystem,windows')
$libraries = @('-lole32','-lwindowscodecs','-luuid','-lbcrypt','-lgdi32','-luser32','-lshell32')
$exe = Join-Path $destination 'KamaitachiChoiceDebug.exe'
& $zig c++ @flags @sources @libraries -o $exe
if ($LASTEXITCODE -ne 0) { throw "Choice debug window build failed ($LASTEXITCODE)" }
$image = [IO.File]::ReadAllBytes($exe)
$pe = [BitConverter]::ToInt32($image,0x3c)
if ([BitConverter]::ToUInt16($image,$pe+24+68) -ne 2) { throw "Expected a Windows GUI subsystem executable" }
foreach ($item in $inputs) {
    if ((Get-FileHash -LiteralPath $item).Hash.ToLowerInvariant() -ne $hashes[$item]) { throw "Build input changed: $item" }
}
$record = [ordered]@{ built_utc=[DateTime]::UtcNow.ToString('o'); compiler_sha256=(Get-FileHash -LiteralPath $zig).Hash
    executable_sha256=(Get-FileHash -LiteralPath $exe).Hash; sources=$hashes; flags=$flags; libraries=$libraries }
[IO.File]::WriteAllText((Join-Path $destination 'build.json'), ($record | ConvertTo-Json -Depth 5))
Get-FileHash -LiteralPath $exe
