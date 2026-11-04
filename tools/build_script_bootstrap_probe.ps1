$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$toolchainRoot = Join-Path $projectRoot 'local\dependencies\ps2recomp\_evaluation'
$zig = Join-Path $toolchainRoot 'toolchain\zig-x86_64-windows-0.15.2\zig.exe'
$env:ZIG_GLOBAL_CACHE_DIR = Join-Path $toolchainRoot 'zig-global-cache'
$env:ZIG_LOCAL_CACHE_DIR = Join-Path $projectRoot 'local\pc-core\bootstrap-zig-local-cache'
$outputRoot = Join-Path $projectRoot 'local\pc-core'
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
$names = @('script_bootstrap','script_image','script_data','source_libc','choice_pipeline','choice')
$sources = @($names | ForEach-Object { Join-Path $projectRoot "port\core\$_.cpp" })
$sources += Join-Path $projectRoot 'port\tools\script_bootstrap_probe.cpp'
$tracked = @($sources) + @($names | ForEach-Object { Join-Path $projectRoot "port\core\$_.hpp" }) +
    @(Join-Path $projectRoot 'port\core\guest_memory.hpp')
$hashes = [ordered]@{}
foreach ($p in $tracked) { $hashes[$p] = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() }
$outputExe = Join-Path $outputRoot 'script_bootstrap_probe.exe'
& $zig c++ -std=c++20 -target x86_64-windows-gnu -O2 -g -fno-fast-math -ffp-contract=off @sources -o $outputExe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
foreach ($p in $tracked) {
    if ((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hashes[$p]) { throw "Source changed during bootstrap build: $p" }
}
$record = [ordered]@{ built_utc=[DateTime]::UtcNow.ToString('o'); sources=$hashes; compiler=$zig
    compiler_sha256=(Get-FileHash -LiteralPath $zig -Algorithm SHA256).Hash.ToLowerInvariant()
    output=$outputExe; output_sha256=(Get-FileHash -LiteralPath $outputExe -Algorithm SHA256).Hash.ToLowerInvariant() }
[IO.File]::WriteAllText((Join-Path $outputRoot 'script_bootstrap_probe.build.json'), ($record | ConvertTo-Json -Depth 5))
Get-FileHash -LiteralPath $outputExe -Algorithm SHA256 | Format-List Path,Hash
