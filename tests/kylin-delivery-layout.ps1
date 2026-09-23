param(
  [string]$DeliveryRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) 'delivery\银河麒麟版')
)

$ErrorActionPreference = 'Stop'

function Assert-FileSet {
  param(
    [string]$Directory,
    [string[]]$ExpectedFiles
  )

  if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
    throw "Missing delivery directory: $Directory"
  }

  $actual = @(Get-ChildItem -LiteralPath $Directory -File | ForEach-Object Name | Sort-Object)
  $expected = @($ExpectedFiles | Sort-Object)
  $difference = @(Compare-Object -ReferenceObject $expected -DifferenceObject $actual)
  if ($difference.Count -ne 0) {
    throw "Unexpected file set in ${Directory}: $($difference | Out-String)"
  }
}

function Assert-Checksums {
  param([string]$Directory)

  $checksumPath = Join-Path $Directory 'SHA256SUMS.txt'
  foreach ($line in Get-Content -LiteralPath $checksumPath) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    if ($line -notmatch '^([0-9a-f]{64})  (.+)$') {
      throw "Invalid checksum line in ${checksumPath}: $line"
    }

    $expectedHash = $Matches[1]
    $fileName = $Matches[2]
    $filePath = Join-Path $Directory $fileName
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
      throw "Checksum references a missing file: $filePath"
    }
    $actualHash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
      throw "Checksum mismatch: $filePath"
    }
  }
}

$rootFiles = @(Get-ChildItem -LiteralPath $DeliveryRoot -File | ForEach-Object Name)
if ($rootFiles.Count -ne 1 -or $rootFiles[0] -ne 'README.md') {
  throw "The Kylin delivery root must contain only README.md: $($rootFiles -join ', ')"
}

$rootDirectories = @(Get-ChildItem -LiteralPath $DeliveryRoot -Directory | ForEach-Object Name | Sort-Object)
$expectedDirectories = @('客户端', '接收端') | Sort-Object
if (@(Compare-Object -ReferenceObject $expectedDirectories -DifferenceObject $rootDirectories).Count -ne 0) {
  throw "The Kylin delivery root must contain only 客户端 and 接收端"
}

$receiverDirectory = Join-Path $DeliveryRoot '接收端'
$clientDirectory = Join-Path $DeliveryRoot '客户端'

Assert-FileSet -Directory $receiverDirectory -ExpectedFiles @(
  'COPYRIGHT.txt',
  'FTP-Receiver.conf',
  'README-FTP接收端.md',
  'README.md',
  'report-receiver-windows-amd64.exe',
  'SHA256SUMS.txt',
  'Start-FTP-Receiver.cmd',
  'Start-FTP-Receiver.ps1'
)

Assert-FileSet -Directory $clientDirectory -ExpectedFiles @(
  'COPYRIGHT.txt',
  'kylin-cleaner-amd64',
  'kylin-cleaner-arm64',
  'kylin-ftp-amd64',
  'kylin-ftp-arm64',
  'kylin-onsite-amd64',
  'kylin-onsite-arm64',
  'README-麒麟测试版.md',
  'README.md',
  'Run-Audit.sh',
  'Run-FTP.sh',
  'Run-Repair.sh',
  'SHA256SUMS.txt',
  '实机测试记录表.md',
  '自动化测试报告.md'
)

Assert-Checksums -Directory $receiverDirectory
Assert-Checksums -Directory $clientDirectory

$rootReadme = Get-Content -LiteralPath (Join-Path $DeliveryRoot 'README.md') -Raw
if ($rootReadme -notmatch 'Windows FTP 接收' -or $rootReadme -notmatch 'Windows 版.*报告管理工具') {
  throw 'The Kylin root README does not describe the shared Windows receiver and report management workflow'
}

$clientReadme = Get-Content -LiteralPath (Join-Path $clientDirectory 'README.md') -Raw
foreach ($launcher in @('Run-Audit.sh', 'Run-Repair.sh', 'Run-FTP.sh')) {
  if ($clientReadme -notmatch [regex]::Escape($launcher)) {
    throw "The client README does not document $launcher"
  }
}

Write-Output 'PASS: Kylin delivery is split into complete, independently verifiable receiver and client packages'
