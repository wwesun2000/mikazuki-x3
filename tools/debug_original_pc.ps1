$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1')
}
$projectRoot = Split-Path $PSScriptRoot -Parent
$probe = Join-Path $projectRoot 'local\pc-core\manager_bootstrap_probe.exe'
if (-not (Test-Path -LiteralPath $probe -PathType Leaf)) { throw 'Build tools\build_manager_bootstrap_probe.ps1 first.' }
Push-Location -LiteralPath $projectRoot
try {
    $elf = 'local\extracted\SLPM_664.52'
    $scenario = 'local\assets\SCENARIO\sn4g.sn4'
    if ((Get-FileHash -LiteralPath $elf).Hash -ne '50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160' -or
        (Get-FileHash -LiteralPath $scenario).Hash -ne 'f0a20139375fadff7e5eb7f10c33f1bd503b4e265752a773035f675d99b628f3' -or
        (Get-FileHash -LiteralPath 'local\assets\SCENARIO\sn4g.fnt').Hash -ne 'c12f602b3716b1dce68d6bdbcb58b45dbe29d67dab0a5ef7dbb35210e3d370b3') { throw 'Unexpected original ELF, scenario or font identity.' }
    # Windows NUL discards the optional RAM dump produced by the analysis probe.
    $raw = & $probe $elf $scenario 0 NUL
    if ($LASTEXITCODE -ne 0) { throw "Native cold-start diagnostic failed ($LASTEXITCODE)." }
    $result = $raw | ConvertFrom-Json
    Write-Host 'Native C++ cold start from the original ELF and sn4g scenario'
    Write-Host ('Entry selector {0}, label ID {1}, offset {2}. Opcode 0x{3:X2} -> ELF function 0x{4:X8}.' -f $result.selector,$result.label_id,$result.entry_offset,[int]$result.opcode,[int]$result.source_target)
    if ($result.first_opcode_completed) {
        Write-Host ("First opcode completed. Committed script steps: " + $result.committed_steps)
        if ($result.yielded) { Write-Host 'Original script yielded to the manager.' }
        elseif ($result.walk_frontier) { Write-Host ('Next frontier (opcode 0x{0:X2}): {1}' -f [int]$result.walk_opcode,$result.walk_frontier) }
    }
    else { Write-Host ('Porting frontier: ' + $result.first_call_frontier) }
} finally {
    Pop-Location
}
