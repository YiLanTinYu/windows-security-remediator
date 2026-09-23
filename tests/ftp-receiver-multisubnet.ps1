param(
  [string]$ScriptPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'delivery\银河麒麟版\接收端\Start-FTP-Receiver.ps1')
)

$ErrorActionPreference = 'Stop'
$temporary = Join-Path $env:TEMP ("ftp-receiver-config-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null

function Write-TestConfig {
  param(
    [string]$PassiveIp,
    [string]$ControlPort,
    [string]$PassiveStart,
    [string]$PassiveEnd,
    [string]$AllowedRemote
  )

  @"
PASSIVE_IP=$PassiveIp
CONTROL_PORT=$ControlPort
PASSIVE_PORT_START=$PassiveStart
PASSIVE_PORT_END=$PassiveEnd
ALLOWED_REMOTE=$AllowedRemote
REPORT_DIRECTORY=reports
"@ | Set-Content -LiteralPath (Join-Path $temporary 'FTP-Receiver.conf') -Encoding UTF8
}

try {
  $testScript = Join-Path $temporary 'Start-FTP-Receiver.ps1'
  $source = [IO.File]::ReadAllText($ScriptPath, [Text.Encoding]::UTF8)
  $source = $source -replace '^#Requires -RunAsAdministrator\r?\n', ''
  [IO.File]::WriteAllText($testScript, $source, [Text.UTF8Encoding]::new($false))
  Copy-Item -LiteralPath "$env:WINDIR\System32\where.exe" -Destination (Join-Path $temporary 'report-receiver-windows-amd64.exe')

  $script:responses = [Collections.Generic.Queue[string]]::new()
  $script:passwords = [Collections.Generic.Queue[string]]::new()
  $script:prompts = [Collections.Generic.List[string]]::new()
  $script:firewallCalls = [Collections.Generic.List[object]]::new()

  function Read-Host {
    param([string]$Prompt, [switch]$AsSecureString)
    $script:prompts.Add($Prompt)
    if ($AsSecureString) {
      return ConvertTo-SecureString $script:passwords.Dequeue() -AsPlainText -Force
    }
    return $script:responses.Dequeue()
  }
  function Get-NetFirewallRule { param([string]$Name) return $null }
  function Remove-NetFirewallRule { process {} }
  function New-NetFirewallRule {
    param(
      [string]$Name, [string]$DisplayName, [string]$Direction, [string]$Action,
      [string]$Protocol, [string]$LocalPort, [string[]]$RemoteAddress
    )
    $script:firewallCalls.Add([pscustomobject]@{
      Name = $Name
      LocalPort = $LocalPort
      RemoteAddress = @($RemoteAddress)
    })
  }

  Write-TestConfig `
    -PassiveIp '192.0.2.10' `
    -ControlPort '13331' `
    -PassiveStart '30000' `
    -PassiveEnd '30009' `
    -AllowedRemote '192.0.2.0/24，198.51.100.0/24; 203.0.113.10 ;192.0.2.0/24'
  $script:responses.Enqueue('synthetic-upload-user')
  $script:passwords.Enqueue('SyntheticPassword-123!')

  try {
    . $testScript
  } catch {
    if ($_.Exception.Message -notmatch '接收程序退出') { throw }
  }

  $plainPrompts = @($script:prompts | Where-Object { $_ -notmatch '密码' })
  if ($plainPrompts.Count -ne 1 -or $plainPrompts[0] -notmatch '账号') {
    throw "Valid configuration should only prompt for the account and password: $($script:prompts -join ' | ')"
  }
  if ($script:firewallCalls.Count -ne 2) {
    throw "Expected two firewall rules, got $($script:firewallCalls.Count)"
  }
  $expected = @('192.0.2.0/24', '198.51.100.0/24', '203.0.113.10')
  foreach ($call in $script:firewallCalls) {
    if (@(Compare-Object -ReferenceObject $expected -DifferenceObject @($call.RemoteAddress)).Count -ne 0) {
      throw "$($call.Name) did not receive the configured remote networks"
    }
  }
  if (($script:firewallCalls | Where-Object Name -eq 'KylinReportFTP-Control').LocalPort -ne '13331') {
    throw 'The configured control port was not applied'
  }
  if (($script:firewallCalls | Where-Object Name -eq 'KylinReportFTP-Passive').LocalPort -ne '30000-30009') {
    throw 'The configured passive range was not applied'
  }

  Write-TestConfig `
    -PassiveIp 'not-an-ip' `
    -ControlPort '70000' `
    -PassiveStart '30010' `
    -PassiveEnd '30009' `
    -AllowedRemote 'not-a-network'
  $script:responses.Clear()
  foreach ($response in @(
    '192.0.2.20', '13331', '30020',
    '192.0.2.0/24,198.51.100.0/24', '', 'corrected-upload-user'
  )) {
    $script:responses.Enqueue($response)
  }
  $script:passwords.Clear()
  $script:passwords.Enqueue('weak')
  $script:passwords.Enqueue('CorrectedPassword-123!')
  $script:prompts.Clear()
  $script:firewallCalls.Clear()

  try {
    . $testScript
  } catch {
    if ($_.Exception.Message -notmatch '接收程序退出') { throw }
  }

  if ($script:responses.Count -ne 0 -or $script:passwords.Count -ne 0) {
    throw 'Invalid configuration values or a weak password were not offered a correction prompt'
  }
  if ($script:firewallCalls.Count -ne 2) {
    throw 'Corrected values did not reach firewall rule creation'
  }
  if (($script:firewallCalls | Where-Object Name -eq 'KylinReportFTP-Passive').LocalPort -ne '30010-30020') {
    throw 'The corrected passive port range was not applied'
  }

  $configText = Get-Content -LiteralPath (Join-Path $temporary 'FTP-Receiver.conf') -Raw
  if ($configText -match '(?im)^\s*(FTP_)?(USER|USERNAME|PASSWORD)\s*=') {
    throw 'The non-sensitive configuration file must not contain an account or password field'
  }

  Write-Output 'PASS: receiver preloads non-sensitive configuration, prompts only for credentials, and allows invalid values to be corrected'
} finally {
  Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
