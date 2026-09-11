param(
    [Parameter(Mandatory = $true)]
    [string]$ClientExe,
    [string]$Server = "127.0.0.1:8443"
)
$ErrorActionPreference = "Stop"
$directory = Split-Path -Parent $ClientExe
$process = Start-Process -FilePath $ClientExe -ArgumentList "/server=$Server" -PassThru -Wait
$statusPath = Join-Path $directory "upload-status.json"
if (-not (Test-Path -LiteralPath $statusPath)) { throw "未生成 upload-status.json" }
$status = Get-Content -Raw -LiteralPath $statusPath | ConvertFrom-Json
if (-not $status.uploaded) {
    throw "HTTPS 上传失败：exit=$($process.ExitCode), stage=$($status.stage), win32=$($status.win32)"
}
Write-Host "PASS: HTTPS report upload completed, exit=$($process.ExitCode)"
