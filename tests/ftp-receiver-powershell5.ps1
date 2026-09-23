param(
  [string]$ScriptPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'delivery\银河麒麟版\接收端\Start-FTP-Receiver.ps1')
)

$ErrorActionPreference = 'Stop'
$resolvedScript = (Resolve-Path -LiteralPath $ScriptPath).Path
$bytes = [IO.File]::ReadAllBytes($resolvedScript)
if ($bytes.Length -lt 3 -or $bytes[0] -ne 0xEF -or $bytes[1] -ne 0xBB -or $bytes[2] -ne 0xBF) {
  throw 'Receiver script must use UTF-8 with BOM so Windows PowerShell 5.1 reads Chinese text safely'
}

$env:FTP_RECEIVER_SCRIPT_TO_PARSE = $resolvedScript
try {
  $command = @'
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
  $env:FTP_RECEIVER_SCRIPT_TO_PARSE,
  [ref]$tokens,
  [ref]$errors
) | Out-Null
if ($errors.Count -gt 0) {
  $errors | ForEach-Object { Write-Error $_.Message }
  exit 1
}
'@
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
  & "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -EncodedCommand $encoded
  if ($LASTEXITCODE -ne 0) {
    throw "Windows PowerShell 5.1 could not parse the receiver script (exit $LASTEXITCODE)"
  }
} finally {
  Remove-Item Env:\FTP_RECEIVER_SCRIPT_TO_PARSE -ErrorAction SilentlyContinue
}

Write-Output 'PASS: receiver script is UTF-8 BOM and parses successfully in Windows PowerShell 5.1'
