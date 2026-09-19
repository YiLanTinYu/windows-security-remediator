param(
  [Parameter(Mandatory = $true)]
  [string]$ExePath
)

$ErrorActionPreference = 'Stop'
$root = Join-Path $env:TEMP ("report-issue-exporter-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null

function Write-Report([string]$Name, [string]$Json) {
  Set-Content -LiteralPath (Join-Path $root $Name) -Value $Json -Encoding UTF8
}

try {
  Copy-Item -LiteralPath $ExePath -Destination (Join-Path $root 'report-issue-exporter.exe')
  $exe = Join-Path $root 'report-issue-exporter.exe'

  Write-Report 'verification-report_10.0.0.1_AA-BB-CC-DD-EE-01_20260910-100000-000.json' @'
{"schema":1,"computer":"PC-OLD","ip":"10.0.0.1","mac":"AA-BB-CC-DD-EE-01","finished":"2026-09-10 10:00:00","passed":1,"failed":1,"review":0,"summary":[{"item":"OLD-ISSUE-MUST-NOT-APPEAR","expected":"normal","actual":"bad","conclusion":"fail"}],"details":[]}
'@
  Write-Report 'verification-report_10.0.0.1_AA-BB-CC-DD-EE-01_20260910-110000-000.json' @'
{"schema":1,"computer":"PC-NEW","ip":"10.0.0.1","mac":"AA-BB-CC-DD-EE-01","finished":"2026-09-10 11:00:00","passed":2,"failed":3,"review":1,"summary":[{"item":"Server 文件共享服务","expected":"stopped","actual":"running","conclusion":"fail"},{"item":"防火墙规则 TCP-445","expected":"one rule","actual":"zero rules","conclusion":"fail"},{"item":"浏览器已保存密码","expected":"zero","actual":"two","conclusion":"fail"},{"item":"External connectivity","expected":"blocked","actual":"local listener","conclusion":"review"},{"item":"RDP service","expected":"stopped","actual":"stopped","conclusion":"pass"}],"details":[]}
'@
  Write-Report 'verification-report_10.0.0.2_AA-BB-CC-DD-EE-02_20260910-120000-000.json' @'
{"schema":1,"computer":"PC-PASS","ip":"10.0.0.2","mac":"AA-BB-CC-DD-EE-02","finished":"2026-09-10 12:00:00","passed":1,"failed":0,"review":0,"summary":[{"item":"Server service","expected":"stopped","actual":"stopped","conclusion":"pass"}],"details":[]}
'@
  Write-Report 'verification-report_10.0.0.3_AA-BB-CC-DD-EE-03_20260910-130000-000.json' @'
{"platform":"Kylin","computer":"KYLIN-NEW","ip":"10.0.0.3","mac":"AA-BB-CC-DD-EE-03","finished":"2026-09-10 13:00:00","summary":[{"item":"高危端口阻断","expected":"blocked","actual":"SENSITIVE-ACTUAL-MUST-NOT-APPEAR","conclusion":"异常"},{"item":"USB存储历史","actual":"SENSITIVE-USB-EVIDENCE-MUST-NOT-APPEAR","conclusion":"需复核"}]}
'@
  Write-Report 'kylin-report_10.0.0.4_AA-BB-CC-DD-EE-04_20260910-140000-000.json' @'
{"identity":{"hostname":"KYLIN-LEGACY","os":"Kylin V10","ip":"10.0.0.4","mac":"AA-BB-CC-DD-EE-04"},"generated_at":"2026-09-10 14:00:00","after_checks":[{"item":"浏览器保存密码","actual":"SENSITIVE-BROWSER-DETAIL-MUST-NOT-APPEAR","conclusion":"异常"}]}
'@
  Write-Report 'upload-status_10.0.0.3_AA-BB-CC-DD-EE-03_20260910-130000-000.json' '{"status":"uploaded"}'
  Set-Content -LiteralPath (Join-Path $root 'unrelated.json') -Value '{"ip":"203.0.113.1"}' -Encoding UTF8
  foreach ($json in Get-ChildItem -LiteralPath $root -Filter '*report_*.json') {
    Set-Content -LiteralPath (Join-Path $root ($json.BaseName + '.html')) -Value '<html>paired report</html>' -Encoding UTF8
  }
  Write-Report 'verification-report_10.0.0.5_AA-BB-CC-DD-EE-05_20260910-150000-000.json' '{broken-json'
  Set-Content -LiteralPath (Join-Path $root 'verification-report_10.0.0.5_AA-BB-CC-DD-EE-05_20260910-150000-000.html') -Value '<html>broken JSON pair</html>' -Encoding UTF8
  Write-Report 'verification-report_10.0.0.6_AA-BB-CC-DD-EE-06_20260910-160000-000.json' '{"computer":"MISSING-HTML-MUST-NOT-APPEAR","ip":"10.0.0.6","mac":"AA-BB-CC-DD-EE-06","summary":[]}'
  foreach ($ip in @('10.0.0.7','10.0.0.8')) {
    $name = "verification-report_${ip}_AA-BB-CC-DD-EE-07_20260910-170000-000"
    Write-Report ($name + '.json') ('{"computer":"CONFLICT-MUST-NOT-APPEAR","ip":"' + $ip + '","mac":"AA-BB-CC-DD-EE-07","summary":[]}')
    Set-Content -LiteralPath (Join-Path $root ($name + '.html')) -Value '<html>conflict pair</html>' -Encoding UTF8
  }
  Set-Content -LiteralPath (Join-Path $root '人员对应表.csv') -Value @'
持有人,组织机构,操作系统,IP,MAC
测试人员甲,信息技术部,Windows 10,10.0.0.1,AA-BB-CC-DD-EE-01
测试人员乙,财务部,Windows 11,10.0.0.2,AA-BB-CC-DD-EE-02
测试人员甲,信息技术部,银河麒麟V10,10.0.0.3,AA-BB-CC-DD-EE-03
测试人员丙,运维部,银河麒麟V10,10.0.0.4,AA-BB-CC-DD-EE-04
'@ -Encoding UTF8

  & $exe (Join-Path $root '人员对应表.csv') | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Unexpected exit code: $LASTEXITCODE" }
  $xlsx = Join-Path $root 'person-security-issues-summary.xlsx'
  if (-not (Test-Path -LiteralPath $xlsx)) { throw 'Missing person-security-issues-summary.xlsx' }

  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [System.IO.Compression.ZipFile]::OpenRead($xlsx)
  try {
    $worksheetEntries = @($zip.Entries | Where-Object { $_.FullName -like 'xl/worksheets/sheet*.xml' })
    if ($worksheetEntries.Count -ne 3) { throw "Expected 3 worksheets, got $($worksheetEntries.Count)" }
    $xml = ''
    foreach ($entry in $worksheetEntries) {
      $reader = New-Object System.IO.StreamReader($entry.Open(), [System.Text.Encoding]::UTF8)
      try { $xml += $reader.ReadToEnd() } finally { $reader.Dispose() }
    }
    $workbookEntry = $zip.GetEntry('xl/workbook.xml')
    $workbookReader = New-Object System.IO.StreamReader($workbookEntry.Open(), [System.Text.Encoding]::UTF8)
    try { $workbookXml = $workbookReader.ReadToEnd() } finally { $workbookReader.Dispose() }
    $stylesEntry = $zip.GetEntry('xl/styles.xml')
    if ($null -eq $stylesEntry) { throw 'Missing styles XML' }
    $stylesReader = New-Object System.IO.StreamReader($stylesEntry.Open(), [System.Text.Encoding]::UTF8)
    try { $stylesXml = $stylesReader.ReadToEnd() } finally { $stylesReader.Dispose() }
  } finally { $zip.Dispose() }

  if (($xml | Select-String -Pattern '>10\.0\.0\.1</t>' -AllMatches).Matches.Count -ne 1) {
    throw 'One IP was not summarized into exactly one row'
  }
  if (($xml | Select-String -Pattern '>10\.0\.0\.2</t>' -AllMatches).Matches.Count -ne 1) {
    throw 'Compliant IP row is missing'
  }
  foreach ($expected in @('PC-NEW','External connectivity','测试人员甲','测试人员乙','测试人员丙','信息技术部','财务部','运维部','组织机构','风险等级','高危','中危','正常','Kylin','KYLIN-NEW','KYLIN-LEGACY','高危端口阻断','浏览器保存密码','源报告文件名')) {
    if ($xml -notmatch [regex]::Escape($expected)) { throw "Missing workbook content: $expected" }
  }
  foreach ($sheetName in @('终端问题汇总','人员问题汇总','统计汇总')) {
    if ($workbookXml -notmatch [regex]::Escape($sheetName)) { throw "Missing worksheet: $sheetName" }
  }
  foreach ($forbidden in @('SENSITIVE-ACTUAL-MUST-NOT-APPEAR','SENSITIVE-USB-EVIDENCE-MUST-NOT-APPEAR','SENSITIVE-BROWSER-DETAIL-MUST-NOT-APPEAR','MISSING-HTML-MUST-NOT-APPEAR','CONFLICT-MUST-NOT-APPEAR','处理建议')) {
    if ($xml -match [regex]::Escape($forbidden)) { throw "Forbidden report detail leaked into workbook: $forbidden" }
  }
  if ($xml -match '原表序号') { throw 'Original sequence column must not be exported' }
  if ($xml -match 'OLD-ISSUE-MUST-NOT-APPEAR') { throw 'Issue from older report was included' }
  if ($xml -notmatch '<autoFilter ' -or $xml -notmatch 'state="frozen"' -or $stylesXml -notmatch 'wrapText="1"') {
    throw 'Workbook is missing filter, frozen headers, or wrapped issue cells'
  }
  if (-not (Test-Path -LiteralPath (Join-Path $root 'issue-summary.log'))) {
    throw 'Missing fixed summary log'
  }
  $summaryLog = Get-Content -Raw -LiteralPath (Join-Path $root 'issue-summary.log')
  foreach ($expectedWarning in @('JSON格式错误或缺少必要字段','缺少配对HTML','同一终端同时间戳冲突')) {
    if ($summaryLog -notmatch [regex]::Escape($expectedWarning)) { throw "Missing summary warning: $expectedWarning" }
  }

  Set-Content -LiteralPath (Join-Path $root '人员对应表.csv') -Value @'
持有人,操作系统,IP,MAC
测试人员甲,Windows 10,10.0.0.1,AA-BB-CC-DD-EE-01
测试人员乙,Windows 11,10.0.0.2,AA-BB-CC-DD-EE-02
测试人员甲,银河麒麟V10,10.0.0.3,AA-BB-CC-DD-EE-03
测试人员丙,银河麒麟V10,10.0.0.4,AA-BB-CC-DD-EE-04
'@ -Encoding UTF8
  & $exe (Join-Path $root '人员对应表.csv') | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Unexpected exit code without organization column: $LASTEXITCODE" }
  $zip = [System.IO.Compression.ZipFile]::OpenRead($xlsx)
  try {
    $entry = $zip.GetEntry('xl/worksheets/sheet1.xml')
    $reader = New-Object System.IO.StreamReader($entry.Open(), [System.Text.Encoding]::UTF8)
    try { $withoutOrganizationXml = $reader.ReadToEnd() } finally { $reader.Dispose() }
  } finally { $zip.Dispose() }
  if ($withoutOrganizationXml -notmatch '组织机构' -or $withoutOrganizationXml -match '信息技术部|财务部') {
    throw 'Optional organization column was not handled correctly'
  }

  Write-Output 'PASS: Windows and Kylin reports are summarized into three detail-free worksheets'
}
finally {
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
