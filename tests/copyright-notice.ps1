param(
  [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
$expected = 'Copyright (C) 2026 倚栏听雨. All rights reserved.'
$temporary = Join-Path $env:TEMP ("copyright-notice-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null

try {
  $windowsDelivery = Join-Path $RepositoryRoot 'delivery\Windows版'
  $windowsExecutables = Get-ChildItem -LiteralPath $windowsDelivery -Recurse -Filter '*.exe' -File
  if ($windowsExecutables.Count -eq 0) {
    throw 'No Windows delivery executables were found'
  }
  foreach ($executable in $windowsExecutables) {
    if ($executable.VersionInfo.LegalCopyright -notmatch 'Copyright.*2026.*倚栏听雨') {
      throw "Missing standardized copyright metadata: $($executable.FullName)"
    }
  }

  $kylinSource = Join-Path $RepositoryRoot 'kylin-security-remediator'
  $previousTelemetry = $env:GOTELEMETRY
  $env:GOTELEMETRY = 'off'
  try {
    Push-Location $kylinSource
    try {
      foreach ($command in @('kylin-onsite', 'kylin-ftp', 'kylin-cleaner')) {
        $outputPath = Join-Path $temporary ($command + '.exe')
        & go build -o $outputPath ("./cmd/" + $command)
        if ($LASTEXITCODE -ne 0) { throw "Failed to build $command" }
        $console = (& $outputPath --definitely-invalid 2>&1 | Out-String)
        if ($console -notmatch [regex]::Escape($expected)) {
          throw "$command did not display the copyright notice"
        }
      }
    } finally {
      Pop-Location
    }
  } finally {
    $env:GOTELEMETRY = $previousTelemetry
  }

  foreach ($relativePath in @(
    'delivery\Windows版\COPYRIGHT.txt',
    'delivery\银河麒麟版\接收端\COPYRIGHT.txt',
    'delivery\银河麒麟版\客户端\COPYRIGHT.txt'
  )) {
    $noticePath = Join-Path $RepositoryRoot $relativePath
    if (-not (Test-Path -LiteralPath $noticePath)) {
      throw "Missing copyright notice: $noticePath"
    }
    $notice = Get-Content -LiteralPath $noticePath -Raw
    if ($notice -notmatch '版权所有人：倚栏听雨' -or $notice -notmatch [regex]::Escape($expected)) {
      throw "Incomplete copyright notice: $noticePath"
    }
  }

  Write-Output 'PASS: Windows metadata, Kylin console output, and delivery notices contain the standardized copyright information'
} finally {
  Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
