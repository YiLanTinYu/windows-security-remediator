param([Parameter(Mandatory=$true)][string]$ServerExe)
$ErrorActionPreference='Stop'
$work=Join-Path $env:TEMP ('sr-server-test-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work|Out-Null
try {
    & $ServerExe /self-test /data=$work
    if($LASTEXITCODE -ne 0){throw "服务端自检失败：$LASTEXITCODE"}
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
