$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$toolchainRoot = Join-Path $projectRoot 'local\dependencies\ps2recomp\_evaluation'
$zig = Join-Path $toolchainRoot 'toolchain\zig-x86_64-windows-0.15.2\zig.exe'
$env:ZIG_GLOBAL_CACHE_DIR = Join-Path $toolchainRoot 'zig-global-cache'
$env:ZIG_LOCAL_CACHE_DIR = Join-Path $projectRoot 'local\pc-core\manager-bootstrap-cache'
$outputRoot = Join-Path $projectRoot 'local\pc-core'
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
& (Join-Path $PSScriptRoot 'python.ps1') (Join-Path $PSScriptRoot 'generate_cold_manager_bindings.py') --check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$core = Join-Path $projectRoot 'port\core'
$sources = @(Get-ChildItem -LiteralPath $core -File -Filter '*.cpp' | ForEach-Object FullName)
$sources += Join-Path $projectRoot 'port\tools\manager_bootstrap_probe.cpp'
$tracked = @($sources) + @(Get-ChildItem -LiteralPath $core -File -Filter '*.hpp' | ForEach-Object FullName)
. (Join-Path $PSScriptRoot 'freeze_port_sources.ps1')
$frozen=Get-PortSourceSnapshot $projectRoot (Join-Path $outputRoot 'manager-bootstrap') $tracked
$inputs=@($sources | ForEach-Object {Join-Path $frozen.Directory $_.Substring($projectRoot.Length+1)})
$outputExe = Join-Path $frozen.Directory 'manager_bootstrap_probe.exe'
& $zig c++ -std=c++20 -target x86_64-windows-gnu -O2 -g -fno-fast-math -ffp-contract=off @inputs -o $outputExe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$record = [ordered]@{built_utc=[DateTime]::UtcNow.ToString('o'); sources=$frozen.Frozen; workspace_sources=$frozen.Originals; compiler=$zig
    compiler_sha256=(Get-FileHash -LiteralPath $zig -Algorithm SHA256).Hash.ToLowerInvariant()
    output=$outputExe; output_sha256=(Get-FileHash -LiteralPath $outputExe -Algorithm SHA256).Hash.ToLowerInvariant()}
Copy-Item -LiteralPath $outputExe -Destination (Join-Path $outputRoot 'manager_bootstrap_probe.exe') -Force
[IO.File]::WriteAllText((Join-Path $frozen.Directory 'build.json'),($record | ConvertTo-Json -Depth 5))
[IO.File]::WriteAllText((Join-Path $outputRoot 'manager_bootstrap_probe.build.json'),($record | ConvertTo-Json -Depth 5))
Get-FileHash -LiteralPath $outputExe -Algorithm SHA256 | Format-List Path,Hash
