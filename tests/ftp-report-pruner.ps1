param(
  [Parameter(Mandatory = $true)]
  [string]$ExePath
)

$ErrorActionPreference = 'Stop'
$root = Join-Path $env:TEMP ("ftp-report-pruner-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null

function Add-TestFile([string]$RelativePath) {
  $path = Join-Path $root $RelativePath
  $parent = Split-Path -Parent $path
  if (-not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent | Out-Null
  }
  Set-Content -LiteralPath $path -Value $RelativePath -Encoding UTF8
}

try {
  Copy-Item -LiteralPath $ExePath -Destination (Join-Path $root 'ftp-report-pruner.exe')
  $exe = Join-Path $root 'ftp-report-pruner.exe'

  foreach ($name in @(
      'verification-report_192.168.1.20_18-3D-2D-C6-47-7B_20260910-100000-000.html',
      'verification-report_192.168.1.20_18-3D-2D-C6-47-7B_20260910-100000-000.json',
      'verification-report_192.168.1.20_18-3D-2D-C6-47-7B_20260910-110000-000.html',
      'verification-report_192.168.1.20_18-3D-2D-C6-47-7B_20260910-110000-000.json',
      'verification-report_192.168.1.21_AA-BB-CC-DD-EE-FF_20260909-090000-000.html',
      'verification-report_192.168.1.21_AA-BB-CC-DD-EE-FF_20260911-090000-000.html',
      'verification-report_192.168.1.21_AA-BB-CC-DD-EE-FF_20260911-090000-000.json',
      'kylin-report_192.0.2.30_02-00-5E-10-00-02_20260910-080000-000.html',
      'kylin-report_192.0.2.30_02-00-5E-10-00-02_20260910-080000-000.json',
      'kylin-report_192.0.2.30_02-00-5E-10-00-02_20260910-090000-000.html',
      'kylin-report_192.0.2.30_02-00-5E-10-00-02_20260910-090000-000.json',
      'verification-report_192.168.1.20_18-3D-2D-C6-47-7B_20260912-120000-000.html',
      'upload-status_192.168.1.20_18-3D-2D-C6-47-7B_20260912-120000-000.json',
      'verification-report_unknown.html',
      'cleanup-report_192.168.1.20_18-3D-2D-C6-47-7B_20260910-100000-000.html',
      'notes.txt')) {
    Add-TestFile $name
  }
  Add-TestFile 'archive\verification-report_192.168.1.20_18-3D-2D-C6-47-7B_20200101-000000-000.html'

  & $exe /preview | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "预览退出码错误：$LASTEXITCODE" }
  if (-not (Test-Path -LiteralPath (Join-Path $root 'verification-report_192.168.1.20_18-3D-2D-C6-47-7B_20260910-100000-000.html'))) {
    throw '预览模式不应删除文件'
  }

  $start = New-Object System.Diagnostics.ProcessStartInfo
  $start.FileName = $exe
  $start.WorkingDirectory = $root
  $start.UseShellExecute = $false
  $start.RedirectStandardInput = $true
  $start.RedirectStandardOutput = $true
  $process = [System.Diagnostics.Process]::Start($start)
  $process.StandardInput.WriteLine('yes')
  $process.StandardInput.Close()
  $process.WaitForExit()
  if ($process.ExitCode -ne 0) { throw "清理退出码错误：$($process.ExitCode)" }

  $deleted = @(
    'verification-report_192.168.1.20_18-3D-2D-C6-47-7B_20260910-100000-000.html',
    'verification-report_192.168.1.20_18-3D-2D-C6-47-7B_20260910-100000-000.json',
    'kylin-report_192.0.2.30_02-00-5E-10-00-02_20260910-080000-000.html',
    'kylin-report_192.0.2.30_02-00-5E-10-00-02_20260910-080000-000.json'
  )
  foreach ($name in $deleted) {
    if (Test-Path -LiteralPath (Join-Path $root $name)) { throw "旧报告未删除：$name" }
  }

  $kept = @(
    'verification-report_192.168.1.20_18-3D-2D-C6-47-7B_20260910-110000-000.html',
    'verification-report_192.168.1.20_18-3D-2D-C6-47-7B_20260910-110000-000.json',
    'verification-report_192.168.1.21_AA-BB-CC-DD-EE-FF_20260911-090000-000.html',
    'verification-report_192.168.1.21_AA-BB-CC-DD-EE-FF_20260911-090000-000.json',
    'verification-report_192.168.1.21_AA-BB-CC-DD-EE-FF_20260909-090000-000.html',
    'kylin-report_192.0.2.30_02-00-5E-10-00-02_20260910-090000-000.html',
    'kylin-report_192.0.2.30_02-00-5E-10-00-02_20260910-090000-000.json',
    'verification-report_192.168.1.20_18-3D-2D-C6-47-7B_20260912-120000-000.html',
    'upload-status_192.168.1.20_18-3D-2D-C6-47-7B_20260912-120000-000.json',
    'verification-report_unknown.html',
    'cleanup-report_192.168.1.20_18-3D-2D-C6-47-7B_20260910-100000-000.html',
    'notes.txt',
    'archive\verification-report_192.168.1.20_18-3D-2D-C6-47-7B_20200101-000000-000.html'
  )
  foreach ($name in $kept) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $name))) { throw "不应删除的文件丢失：$name" }
  }
  if (-not (Test-Path -LiteralPath (Join-Path $root 'report-cleanup.log'))) {
    throw '未生成固定名称的中文清理日志'
  }
  $log = Get-Content -LiteralPath (Join-Path $root 'report-cleanup.log') -Raw
  if ($log -notmatch '20260912-120000-000.html') { throw 'Cleanup log did not mention the preserved incomplete report' }

  Write-Output 'PASS: FTP report pruner keeps newest complete Windows/Kylin batches and preserves incomplete/unknown files'
}
finally {
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
