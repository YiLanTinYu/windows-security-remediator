param(
    [Parameter(Mandatory=$true)][string]$InspectorPath,
    [Parameter(Mandatory=$true)][string]$VerifierPath
)

$ErrorActionPreference='Stop'
if(!(Test-Path -LiteralPath $InspectorPath)){throw "找不到现场检查程序：$InspectorPath"}
$directory=Split-Path -Parent $InspectorPath
Copy-Item -LiteralPath $VerifierPath -Destination (Join-Path $directory 'verify-remediator.ps1') -Force
Get-ChildItem -LiteralPath $directory -Filter 'verification-report*.html' -ErrorAction SilentlyContinue | Remove-Item -Force

$process=Start-Process -FilePath $InspectorPath -ArgumentList @('/no-pause','/no-open') -Wait -PassThru -WindowStyle Hidden
if($process.ExitCode -ne 0 -and $process.ExitCode -ne 5){throw "现场检查程序返回非预期退出码：$($process.ExitCode)"}
$reports=@(Get-ChildItem -LiteralPath $directory -Filter 'verification-report_*.html' -ErrorAction SilentlyContinue)
if($reports.Count -ne 1){throw "现场检查程序结束后应生成一份带 IP/MAC 文件名的报告，实际为 $($reports.Count) 份。"}
$report=$reports[0].FullName
$html=[IO.File]::ReadAllText($report)
if(!$html.Contains('六、浏览器已保存密码逐项明细')){throw '现场检查程序生成的报告缺少浏览器检查。'}
if($html -notmatch '被检查终端IP地址:[^<]+  MAC地址：[^<]+'){throw '现场检查程序生成的报告缺少终端 IP/MAC。'}

Write-Host 'PASS：现场检查 EXE 等待检查结束并生成完整报告。'
