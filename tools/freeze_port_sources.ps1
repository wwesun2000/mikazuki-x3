# A build and its evidence retain the exact source bytes even while another
# recovered function is being implemented in the working directory.
function Get-PortSourceSnapshot($project,$destination,$files) {
    $hashes=[ordered]@{}
    foreach($inputFile in $files){$hashes[$inputFile]=(Get-FileHash -LiteralPath $inputFile).Hash.ToLowerInvariant()}
    $keys=($hashes.Keys | Sort-Object | ForEach-Object { "$($_.Substring($project.Length)) $($hashes[$_])" }) -join [char]10
    $digest=[Security.Cryptography.SHA256]::Create()
    try {$id=([BitConverter]::ToString($digest.ComputeHash([Text.Encoding]::UTF8.GetBytes($keys)))).Replace('-','').ToLowerInvariant()}
    finally {$digest.Dispose()}
    $directory=Join-Path $destination ("builds/"+$id)
    $frozen=[ordered]@{}
    foreach($original in $hashes.Keys) {
        $copy=Join-Path $directory $original.Substring($project.Length+1)
        if(-not (Test-Path -LiteralPath $copy)){
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $copy) | Out-Null
            Copy-Item -LiteralPath $original -Destination $copy
        }
        if((Get-FileHash -LiteralPath $copy).Hash -ne $hashes[$original]){throw "Source changed during snapshot: $original"}
        $frozen[$copy]=$hashes[$original]
    }
    [PSCustomObject]@{ Directory=$directory; Id=$id; Originals=$hashes; Frozen=$frozen }
}
