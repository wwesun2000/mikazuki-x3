$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$toolchainRoot = Join-Path $projectRoot 'local\dependencies\ps2recomp\_evaluation'
$zig = Join-Path $toolchainRoot 'toolchain\zig-x86_64-windows-0.15.2\zig.exe'
$env:ZIG_GLOBAL_CACHE_DIR = Join-Path $toolchainRoot 'zig-global-cache'
$env:ZIG_LOCAL_CACHE_DIR = Join-Path $projectRoot 'local\pc-core\zig-local-cache'
$outputRoot = Join-Path $projectRoot 'local\pc-core'
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
$core = Join-Path $projectRoot 'port/core'
$sources = @(Get-ChildItem -LiteralPath $core -File -Filter '*.cpp' | ForEach-Object FullName) + @(
    (Join-Path $projectRoot 'port/tools/core_probe.cpp')
)
$sourceFiles = @($sources) + @(Get-ChildItem -LiteralPath $core -File -Filter '*.hpp' | ForEach-Object FullName) + @(
    (Join-Path $projectRoot 'port\tests\media_active_contracts.cpp'),
    (Join-Path $projectRoot 'port\tests\source_sound_worker.cpp'),
    (Join-Path $projectRoot 'port\tools\script_index_probe.cpp'),
    (Join-Path $projectRoot 'port\tools\core_walk.cpp'),
    (Join-Path $projectRoot 'port\tools\state_call_probe.cpp'),
    (Join-Path $projectRoot 'port\tests\core_contracts.cpp')
)
. (Join-Path $PSScriptRoot 'freeze_port_sources.ps1')
$frozen=Get-PortSourceSnapshot $projectRoot (Join-Path $outputRoot 'central') $sourceFiles
$buildRoot=$frozen.Directory
$sources=@($sources | ForEach-Object {Join-Path $buildRoot $_.Substring($projectRoot.Length+1)})
$outputExe=Join-Path $buildRoot 'core_probe.exe'
& $zig c++ -std=c++20 -target x86_64-windows-gnu -O2 -g -fno-fast-math -ffp-contract=off @sources -o $outputExe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$stateCallSource = Join-Path $buildRoot 'port\tools\state_call_probe.cpp'
$stateCallExe = Join-Path $buildRoot 'state_call_probe.exe'
$stateCallCoreSources = @($sources | Where-Object { $_ -notlike '*core_probe.cpp' })
& $zig c++ -std=c++20 -target x86_64-windows-gnu -O2 -g -fno-fast-math -ffp-contract=off @stateCallCoreSources $stateCallSource -o $stateCallExe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$walkerSource = Join-Path $buildRoot 'port\tools\core_walk.cpp'
$walkerExe = Join-Path $buildRoot 'core_walk.exe'
$walkerCoreSources = @($sources | Where-Object { $_ -notlike '*core_probe.cpp' })
& $zig c++ -std=c++20 -target x86_64-windows-gnu -O2 -g -fno-fast-math -ffp-contract=off @walkerCoreSources $walkerSource -o $walkerExe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$coreSources = @($sources | Where-Object { $_ -notlike '*core_probe.cpp' })
$contractSource = Join-Path $buildRoot 'port\tests\core_contracts.cpp'
$contractExe = Join-Path $buildRoot 'core_contracts.exe'
& $zig c++ -std=c++20 -target x86_64-windows-gnu -O2 -g -fno-fast-math -ffp-contract=off @coreSources $contractSource -o $contractExe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$contractDirectory = Join-Path $outputRoot ('contract-test-' + [Guid]::NewGuid().ToString('N'))
& $contractExe $contractDirectory
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$mediaContractSource = Join-Path $buildRoot 'port\tests\media_active_contracts.cpp'
$mediaContractExe = Join-Path $buildRoot 'media_active_contracts.exe'
& $zig c++ -std=c++20 -target x86_64-windows-gnu -O2 -g -fno-fast-math -ffp-contract=off @coreSources $mediaContractSource -o $mediaContractExe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $mediaContractExe (Join-Path $projectRoot 'local\extracted\SLPM_664.52')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$soundExe=Join-Path $buildRoot 'source_sound_worker.exe'
$soundTest=Join-Path $buildRoot 'port/tests/source_sound_worker.cpp'
& $zig c++ -std=c++20 -target x86_64-windows-gnu -O2 -g -fno-fast-math -ffp-contract=off @coreSources $soundTest -o $soundExe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $soundExe (Join-Path $projectRoot 'local/assets/SOUND/SSDVDAT/se.dat')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$indexSource = Join-Path $buildRoot 'port\tools\script_index_probe.cpp'
$indexExe = Join-Path $buildRoot 'script_index_probe.exe'
& $zig c++ -std=c++20 -target x86_64-windows-gnu -O2 -g -fno-fast-math -ffp-contract=off @coreSources $indexSource -o $indexExe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
foreach ($binary in @($outputExe,$stateCallExe,$walkerExe,$contractExe,$mediaContractExe,$indexExe)) {
    Copy-Item -LiteralPath $binary -Destination (Join-Path $outputRoot (Split-Path $binary -Leaf)) -Force
}
$buildRecord = [ordered]@{
    built_utc = [DateTime]::UtcNow.ToString('o')
    compiler = $zig
    compiler_sha256 = (Get-FileHash -LiteralPath $zig -Algorithm SHA256).Hash.ToLowerInvariant()
    flags = @('c++','-std=c++20','-target','x86_64-windows-gnu','-O2','-g','-fno-fast-math','-ffp-contract=off')
    sources = $frozen.Frozen
    workspace_sources = $frozen.Originals
    output = $outputExe
    output_sha256 = (Get-FileHash -LiteralPath $outputExe -Algorithm SHA256).Hash.ToLowerInvariant()
    contracts_output = $contractExe
    contracts_sha256 = (Get-FileHash -LiteralPath $contractExe -Algorithm SHA256).Hash.ToLowerInvariant()
    contracts_passed = $true
    contracts_directory = $contractDirectory
    walker_output = $walkerExe
    walker_sha256 = (Get-FileHash -LiteralPath $walkerExe -Algorithm SHA256).Hash.ToLowerInvariant()
    index_output = $indexExe
    index_sha256 = (Get-FileHash -LiteralPath $indexExe -Algorithm SHA256).Hash.ToLowerInvariant()
    state_call_output = $stateCallExe
    state_call_sha256 = (Get-FileHash -LiteralPath $stateCallExe -Algorithm SHA256).Hash.ToLowerInvariant()
    media_contracts_passed = $true
    sound_contracts_passed = $true
    sound_contracts_sha256 = (Get-FileHash -LiteralPath $soundExe -Algorithm SHA256).Hash.ToLowerInvariant()
    media_contracts_sha256 = (Get-FileHash -LiteralPath $mediaContractExe -Algorithm SHA256).Hash.ToLowerInvariant()
}
[IO.File]::WriteAllText((Join-Path $buildRoot 'build.json'), ($buildRecord | ConvertTo-Json -Depth 5))
[IO.File]::WriteAllText((Join-Path $outputRoot 'core_probe.build.json'), ($buildRecord | ConvertTo-Json -Depth 5))
Get-FileHash -LiteralPath $outputExe -Algorithm SHA256 | Format-List Path,Hash
