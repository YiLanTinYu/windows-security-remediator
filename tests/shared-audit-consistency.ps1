param(
    [Parameter(Mandatory=$true)][string]$FieldInspector,
    [Parameter(Mandatory=$true)][string]$RemoteInspector
)
$ErrorActionPreference='Stop'
$root=Join-Path $env:TEMP ('sr-shared-audit-'+[guid]::NewGuid().ToString('N'))
$fieldDir=Join-Path $root 'field'
$remoteDir=Join-Path $root 'remote'
New-Item -ItemType Directory -Path $fieldDir,$remoteDir -Force|Out-Null
try {
    $field=Join-Path $fieldDir 'field.exe'
    $remote=Join-Path $remoteDir 'remote.exe'
    Copy-Item -LiteralPath $FieldInspector -Destination $field
    Copy-Item -LiteralPath $RemoteInspector -Destination $remote
    $p=Start-Process -FilePath $field -ArgumentList '/audit-only','/no-open','/no-pause' -WorkingDirectory $fieldDir -Wait -PassThru
    if($p.ExitCode -notin 0,5){throw "Onsite audit failed: $($p.ExitCode)"}
    $p=Start-Process -FilePath $remote -ArgumentList '/local-only','/audit-only' -WorkingDirectory $remoteDir -Wait -PassThru
    if($p.ExitCode -notin 0,5){throw "FTP local audit failed: $($p.ExitCode)"}
    $fieldJson=Get-Content -Raw -LiteralPath (Get-ChildItem $fieldDir -Filter 'verification-report_*.json'|Select-Object -First 1).FullName|ConvertFrom-Json
    $remoteJson=Get-Content -Raw -LiteralPath (Get-ChildItem $remoteDir -Filter 'verification-report_*.json'|Select-Object -First 1).FullName|ConvertFrom-Json
    foreach($part in 'summary','details') {
        $a=$fieldJson.$part|ConvertTo-Json -Depth 20 -Compress
        $b=$remoteJson.$part|ConvertTo-Json -Depth 20 -Compress
        if($a -ne $b){throw "Onsite and FTP $part differ"}
    }
    Write-Host 'PASS: onsite and FTP use the same audit result.'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
