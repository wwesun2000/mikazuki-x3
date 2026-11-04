param([switch]$MenuProbe,[switch]$NameProbe,[switch]$OverlayProbe)
$ErrorActionPreference = 'Stop'
$project = Split-Path $PSScriptRoot -Parent
$toolchain = Join-Path $project 'local/dependencies/ps2recomp/_evaluation'
$zig = Join-Path $toolchain 'toolchain/zig-x86_64-windows-0.15.2/zig.exe'
$env:ZIG_GLOBAL_CACHE_DIR = Join-Path $toolchain 'zig-global-cache'
$name = if ($OverlayProbe) {'source-overlays'} elseif ($NameProbe) { 'name-entry' } elseif ($MenuProbe) { 'system-menu' } else { 'cold-story' }
$destination = Join-Path $project ("local/pc-core/"+$name)
$env:ZIG_LOCAL_CACHE_DIR = Join-Path $destination 'zig-cache'
New-Item -Force -ItemType Directory -Path $destination | Out-Null
$core = Join-Path $project 'port/core'
$sources = @(Get-ChildItem -LiteralPath $core -Filter '*.cpp' -File | ForEach-Object FullName)
$sources += @('port/platform/windows/project_game.cpp','port/platform/windows/project_media.cpp','port/platform/windows/project_movie.cpp','port/platform/windows/project_audio.cpp','port/platform/windows/project_checkpoint.cpp',
              'port/platform/windows/raster_loader.cpp','port/platform/windows/source_codec.cpp') |
    ForEach-Object { Join-Path $project $_ }
$probe=if($OverlayProbe){'port/tests/scene_overlays_from_file.cpp'}elseif($NameProbe){'port/tests/name_from_file.cpp'}elseif($MenuProbe){'port/tests/system_menu_from_file.cpp'}else{'port/tools/cold_story_probe.cpp'}
$sources+=Join-Path $project $probe
if($OverlayProbe){$sources+=Join-Path $project 'port/platform/windows/window_drawing.cpp'}
$headers = @('port/core','port/platform','port/platform/windows') | ForEach-Object {
    Get-ChildItem -LiteralPath (Join-Path $project $_) -Filter '*.hpp' -File | ForEach-Object FullName
}
. (Join-Path $PSScriptRoot 'freeze_port_sources.ps1')
$frozen=Get-PortSourceSnapshot $project $destination (@($sources)+@($headers))
$hashes=$frozen.Originals
$snapshot=$frozen.Directory
$snapshotId=$frozen.Id
$sourceSnapshot=@($sources | ForEach-Object {Join-Path $snapshot $_.Substring($project.Length+1)})
$exe = Join-Path $destination 'cold_story_probe.exe'
$builtExe=Join-Path $snapshot 'cold_story_probe.exe'
$overlayLibs=if($OverlayProbe){@('-lgdi32','-luser32')}else{@()}
& $zig c++ -std=c++20 -target x86_64-windows-gnu -O2 -g -fno-fast-math -ffp-contract=off @sourceSnapshot -lole32 -lwindowscodecs -luuid -lbcrypt -lwinmm @overlayLibs -o $builtExe
if ($LASTEXITCODE) { exit $LASTEXITCODE }
$changed=@($hashes.Keys | Where-Object {(Get-FileHash -LiteralPath $_).Hash -ne $hashes[$_]})
$pending=Join-Path $destination ("cold-story-"+[Guid]::NewGuid().ToString('N')+".exe")
$build=[ordered]@{ built_utc=[DateTime]::UtcNow.ToString('o'); compiler_sha256=(Get-FileHash -LiteralPath $zig).Hash
    output=$builtExe; output_sha256=(Get-FileHash -LiteralPath $builtExe).Hash; sources=$hashes
    snapshot=$snapshot; snapshot_id=$snapshotId; changed_in_workspace_during_build=$changed }
[IO.File]::WriteAllText((Join-Path $snapshot 'build.json'), ($build | ConvertTo-Json -Depth 4))
Copy-Item -LiteralPath $builtExe -Destination $pending
try {
    $until=[DateTime]::UtcNow.AddMinutes(2)
    while($true){
        try{[IO.File]::Move($pending,$exe,$true);break}
        catch [IO.IOException]{if([DateTime]::UtcNow -ge $until){throw};Start-Sleep -Milliseconds 500}
        catch [UnauthorizedAccessException]{if([DateTime]::UtcNow -ge $until){throw};Start-Sleep -Milliseconds 500}
    }
} finally {if(Test-Path -LiteralPath $pending){Remove-Item -LiteralPath $pending}}
[IO.File]::WriteAllText((Join-Path $destination 'build.json'), ($build | ConvertTo-Json -Depth 4))
Get-FileHash -LiteralPath $exe
