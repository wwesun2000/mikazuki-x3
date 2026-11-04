# Freeze the exact inputs for a source differential while adjacent ports are being edited.
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$snapshot=Join-Path $root ('local/pc-core/state-call-proof-'+[guid]::NewGuid().ToString('N'))
$toolchain=Join-Path $root 'local/dependencies/ps2recomp/_evaluation'
$compiler=Join-Path $toolchain 'toolchain/zig-x86_64-windows-0.15.2/zig.exe'
$env:ZIG_GLOBAL_CACHE_DIR=Join-Path $toolchain 'zig-global-cache'
$env:ZIG_LOCAL_CACHE_DIR=Join-Path $root 'local/pc-core/state-call-zig-cache'
$null=New-Item -ItemType Directory -Path "$snapshot/port/core","$snapshot/port/tools"
$originals=@(Get-ChildItem -LiteralPath "$root/port/core" -File | Where-Object {$_.Extension -in '.cpp','.hpp'})
$originals+=Get-Item -LiteralPath "$root/port/tools/state_call_probe.cpp"
$sources=@();$hashes=[ordered]@{};$relativeHashes=[ordered]@{}
foreach($file in $originals){
    $relative=$file.FullName.Substring($root.Length+1)
    $copy=Join-Path $snapshot $relative
    Copy-Item -LiteralPath $file.FullName -Destination $copy
    $hashes[$copy]=(Get-FileHash -LiteralPath $copy).Hash.ToLowerInvariant()
    $relativeHashes[$relative]=$hashes[$copy]
    if($file.Extension -eq '.cpp'){$sources+=$copy}
}
foreach($relative in $relativeHashes.Keys){
    if((Get-FileHash -LiteralPath (Join-Path $root $relative)).Hash -ne $relativeHashes[$relative]){
        throw "Source changed while collecting snapshot: $relative"
    }
}
$flags=@('c++','-std=c++20','-target','x86_64-windows-gnu','-O2','-g','-fno-fast-math','-ffp-contract=off')
$exe=Join-Path $snapshot 'state_call_probe.exe'
& $compiler @flags @sources -o $exe
if($LASTEXITCODE){exit $LASTEXITCODE}
foreach($name in $hashes.Keys){
    if((Get-FileHash -LiteralPath $name).Hash -ne $hashes[$name]){throw "Snapshot changed: $name"}
}
$record=[ordered]@{compiler=$compiler;compiler_sha256=(Get-FileHash -LiteralPath $compiler).Hash.ToLowerInvariant()
    flags=$flags;project_relative_sources=$relativeHashes;sources=$hashes;state_call_output=$exe
    state_call_sha256=(Get-FileHash -LiteralPath $exe).Hash.ToLowerInvariant()}
$manifest=Join-Path $snapshot 'build.json'
[IO.File]::WriteAllText($manifest,($record|ConvertTo-Json -Depth 5))
$manifest
