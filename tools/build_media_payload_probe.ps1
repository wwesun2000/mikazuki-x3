$ErrorActionPreference='Stop'
$projectRoot=Split-Path $PSScriptRoot -Parent
$toolchain=Join-Path $projectRoot 'local/dependencies/ps2recomp/_evaluation'
$zig=Join-Path $toolchain 'toolchain/zig-x86_64-windows-0.15.2/zig.exe'
$env:ZIG_GLOBAL_CACHE_DIR=Join-Path $toolchain 'zig-global-cache'
$env:ZIG_LOCAL_CACHE_DIR=Join-Path $projectRoot 'local/pc-core/state-call-zig-cache'
$output=Join-Path $projectRoot 'local/pc-core/media_payload_probe.exe'
$sources=@('port/core/media_active.cpp','port/core/pss_audio.cpp','port/core/sab_animation.cpp','port/tools/media_payload_probe.cpp') |
    ForEach-Object {Join-Path $projectRoot $_}
$headers=@('media_active','source_movie','media_command','guest_memory','pss_audio','sab_animation') |
    ForEach-Object {Join-Path $projectRoot "port/core/$_.hpp"}
$hashes=[ordered]@{}
$headers+=@('sab_layer','raster_frame','gs_blend') | ForEach-Object {Join-Path $projectRoot "port/platform/$_.hpp"}
foreach($file in @($sources)+@($headers)){$hashes[$file]=(Get-FileHash -LiteralPath $file).Hash.ToLowerInvariant()}
$flags=@('c++','-std=c++20','-target','x86_64-windows-gnu','-O2','-fno-fast-math','-ffp-contract=off')
& $zig @flags @sources -o $output
if($LASTEXITCODE){exit $LASTEXITCODE}
foreach($file in $hashes.Keys){if((Get-FileHash -LiteralPath $file).Hash -ne $hashes[$file]){throw "Source changed during build: $file"}}
$receipt=[ordered]@{output=$output;output_sha256=(Get-FileHash -LiteralPath $output).Hash.ToLowerInvariant()
    compiler_sha256=(Get-FileHash -LiteralPath $zig).Hash.ToLowerInvariant();flags=$flags;sources=$hashes}
[IO.File]::WriteAllText((Join-Path $projectRoot 'local/pc-core/media_payload_probe.build.json'),($receipt|ConvertTo-Json -Depth 4))
