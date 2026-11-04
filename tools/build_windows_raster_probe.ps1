$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$toolchainRoot = Join-Path $projectRoot 'local\dependencies\ps2recomp\_evaluation'
$zig = Join-Path $toolchainRoot 'toolchain\zig-x86_64-windows-0.15.2\zig.exe'
$env:ZIG_GLOBAL_CACHE_DIR = Join-Path $toolchainRoot 'zig-global-cache'
$env:ZIG_LOCAL_CACHE_DIR = Join-Path $projectRoot 'local\pc-core\raster-zig-local-cache'
$outputRoot = Join-Path $projectRoot 'local\pc-core'
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
$sources = @(
    (Join-Path $projectRoot 'port\platform\windows\raster_loader.cpp'),
    (Join-Path $projectRoot 'port\tools\raster_probe.cpp')
)
$tracked = @($sources) + @(
    (Join-Path $projectRoot 'port\core\retail_disc.hpp'),
    (Join-Path $projectRoot 'port\platform\windows\raster_loader.hpp'),
    (Join-Path $projectRoot 'port\platform\raster_frame.hpp')
)
$hashes = [ordered]@{}
foreach ($path in $tracked) { $hashes[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
$outputExe = Join-Path $outputRoot 'raster_probe.exe'
& $zig c++ -std=c++20 -target x86_64-windows-gnu -O2 -g -municode @sources -lole32 -lwindowscodecs -luuid -lbcrypt -o $outputExe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
foreach ($path in $tracked) {
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hashes[$path]) { throw "Source changed during raster build: $path" }
}
$record = [ordered]@{
    built_utc = [DateTime]::UtcNow.ToString('o')
    compiler = $zig
    compiler_sha256 = (Get-FileHash -LiteralPath $zig -Algorithm SHA256).Hash.ToLowerInvariant()
    sources = $hashes
    flags = @('-std=c++20','-target','x86_64-windows-gnu','-O2','-g','-municode','-lole32','-lwindowscodecs','-luuid','-lbcrypt')
    output = $outputExe
    output_sha256 = (Get-FileHash -LiteralPath $outputExe -Algorithm SHA256).Hash.ToLowerInvariant()
}
[IO.File]::WriteAllText((Join-Path $outputRoot 'raster_probe.build.json'), ($record | ConvertTo-Json -Depth 5))
Get-FileHash -LiteralPath $outputExe -Algorithm SHA256 | Format-List Path,Hash
