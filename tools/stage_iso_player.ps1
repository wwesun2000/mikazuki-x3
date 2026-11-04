$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$destination=Join-Path $root 'local/windows-iso-player'
$build=Get-Content -Raw -LiteralPath (Join-Path $root 'local/pc-core/player/build.json') | ConvertFrom-Json
$files=[ordered]@{
    'local/dependencies/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe'='2ce797a0f88d7f067180338fb227f7b1928ea727bd9a4d7a1d022f7c52af71a3'
    'Play-PC.cmd'=(Get-FileHash -LiteralPath (Join-Path $root 'Play-PC.cmd')).Hash
    'local/pc-core/player/KamaitachiX3.exe'=$build.executable_sha256
    'docs/PLAYER_README.txt'=(Get-FileHash -LiteralPath (Join-Path $root 'docs/PLAYER_README.txt')).Hash
}
foreach($name in $files.Keys){
    $source=Join-Path $root $name
    if($name -eq 'local/pc-core/player/KamaitachiX3.exe' -and $build.frozen_exe){$source=$build.frozen_exe}
    $target=Join-Path $destination $(if($name -eq 'docs/PLAYER_README.txt'){'README.txt'}else{$name})
    if((Get-FileHash -LiteralPath $source).Hash -ne $files[$name]){throw "Unexpected build input: $name"}
    if((Test-Path -LiteralPath $target) -and (Get-FileHash -LiteralPath $target).Hash -eq $files[$name]){continue}
    $null=New-Item -ItemType Directory -Force -Path (Split-Path $target)
    $pending=$target+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
    try {
        [IO.File]::Copy($source,$pending)
        if((Get-FileHash -LiteralPath $pending).Hash -ne $files[$name]){throw "Staging hash mismatch: $name"}
        [IO.File]::Move($pending,$target,$true)
    } finally {if(Test-Path -LiteralPath $pending){Remove-Item -LiteralPath $pending}}
}
Write-Output (Join-Path $destination 'Play-PC.cmd')
