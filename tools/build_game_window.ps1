$ErrorActionPreference='Stop'
$projectRoot=Split-Path $PSScriptRoot -Parent
$toolchain=Join-Path $projectRoot 'local/dependencies/ps2recomp/_evaluation'
$zig=Join-Path $toolchain 'toolchain/zig-x86_64-windows-0.15.2/zig.exe'
$out=Join-Path $projectRoot 'local/pc-core/player'
$env:ZIG_GLOBAL_CACHE_DIR=Join-Path $toolchain 'zig-global-cache'
$env:ZIG_LOCAL_CACHE_DIR=Join-Path $out 'zig-cache'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$localeTool=Join-Path $PSScriptRoot 'generate_story_locales.py'
$reviewInputs=@((Join-Path $PSScriptRoot 'audit_player_locales.py'))
$reviewInputs+=@((Join-Path $PSScriptRoot 'completed_text_notes.py'),
    (Join-Path $projectRoot 'localization/reveal/completed-notes.zh.json'),
    (Join-Path $projectRoot 'localization/reveal/completed-notes.en.json'))
$reviewFile=Join-Path $projectRoot 'localization/review/player-zh-Hans.json'
if(Test-Path -LiteralPath $reviewFile){$reviewInputs+=$reviewFile}
$localeData=Join-Path $out 'story_locale_data.inc'
$systemData=Join-Path $out 'system_locale_data.inc'
$lock=[IO.File]::Open((Join-Path $out '.build.lock'),'OpenOrCreate','ReadWrite','None')
try{
& (Join-Path $PSScriptRoot 'python.ps1') -B $localeTool $localeData $systemData
if($LASTEXITCODE -ne 0){throw 'Original-script translation binding failed'}
$sources=@(Get-ChildItem -LiteralPath (Join-Path $projectRoot 'port/core') -Filter '*.cpp' -File | ForEach-Object FullName)
$platform=@('port/platform/text_layer.cpp','port/platform/story_localization.cpp','port/platform/windows/game_window.cpp','port/platform/windows/project_game.cpp',
    'port/platform/windows/project_audio.cpp','port/platform/windows/project_checkpoint.cpp','port/platform/windows/source_codec.cpp',
    'port/platform/windows/project_media.cpp','port/platform/windows/project_movie.cpp','port/platform/windows/project_font.cpp','port/platform/windows/raster_loader.cpp',
    'port/platform/windows/window_drawing.cpp','port/platform/windows/story_text_layout.cpp')
$sources+=@($platform | ForEach-Object {Join-Path $projectRoot $_})
$headers=@('port/core','port/platform','port/platform/windows') | ForEach-Object {
    Get-ChildItem -LiteralPath (Join-Path $projectRoot $_) -Filter '*.hpp' -File | ForEach-Object FullName
}
. (Join-Path $PSScriptRoot 'freeze_port_sources.ps1')
$frozen=Get-PortSourceSnapshot $projectRoot $out (@($sources)+@($headers)+@($localeTool,$localeData,$systemData)+$reviewInputs)
$hashes=$frozen.Originals
$snapshot=$frozen.Directory
$compileSources=@($sources|ForEach-Object {Join-Path $snapshot $_.Substring($projectRoot.Length+1)})
$inc=Join-Path $snapshot $out.Substring($projectRoot.Length+1)
$flags=@('-std=c++20','-target','x86_64-windows-gnu','-O2','-g','-I',$inc,'-fno-fast-math','-ffp-contract=off',
    '-DUNICODE','-D_UNICODE','-municode','-Wl,--subsystem,windows')
$libs=@('-lole32','-lwindowscodecs','-luuid','-lbcrypt','-lgdi32','-luser32','-lshell32','-lmsimg32','-lwinmm','-luxtheme','-lcomdlg32')
$exe=Join-Path $out 'KamaitachiX3.exe'
$stage=Join-Path $out 'staging'
New-Item -ItemType Directory -Force -Path $stage | Out-Null
$staged=Join-Path $stage 'KamaitachiX3.exe'
& $zig c++ @flags @compileSources @libs -o $staged
if($LASTEXITCODE -ne 0){throw 'Player build failed'}
$changed=@()
foreach($f in $hashes.Keys){
    if((Get-FileHash -LiteralPath (Join-Path $snapshot $f.Substring($projectRoot.Length+1))).Hash -ne $hashes[$f]){throw "Build snapshot changed: $f"}
    if((Get-FileHash -LiteralPath $f).Hash -ne $hashes[$f]){$changed+=$f}
}
$binaryHash=(Get-FileHash -LiteralPath $staged).Hash
$archive=Join-Path $snapshot ('bin/'+$binaryHash)
$null=New-Item -ItemType Directory -Force -Path $archive
$frozenExe=Join-Path $archive 'KamaitachiX3.exe'
if(!(Test-Path -LiteralPath $frozenExe)){[IO.File]::Copy($staged,$frozenExe)}
if((Get-FileHash -LiteralPath $frozenExe).Hash -ne $binaryHash){throw 'Frozen player hash mismatch'}
if(Test-Path -LiteralPath $exe){[IO.File]::Replace($staged,$exe,[NullString]::Value)}
else{[IO.File]::Move($staged,$exe)}
$record=[ordered]@{built_utc=[DateTime]::UtcNow.ToString('o');exe=$exe;frozen_exe=$frozenExe;executable_sha256=$binaryHash
    compiler_sha256=(Get-FileHash -LiteralPath $zig).Hash;sources=$hashes;flags=$flags;libraries=$libs
    compiled_from=$snapshot;working_sources_changed_after_snapshot=$changed}
$json=$record|ConvertTo-Json -Depth 5
if(!(Test-Path -LiteralPath (Join-Path $archive 'build.json'))){[IO.File]::WriteAllText((Join-Path $archive 'build.json'),$json)}
$manifest=Join-Path $stage 'build.json'
[IO.File]::WriteAllText($manifest,$json)
[IO.File]::Move($manifest,(Join-Path $out 'build.json'),$true)
Get-FileHash -LiteralPath $exe
}finally{$lock.Dispose()}
