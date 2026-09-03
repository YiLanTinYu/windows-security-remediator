param(
    [Parameter(Mandatory=$true)][string]$InspectorPath,
    [Parameter(Mandatory=$true)][string]$VerifierPath
)

$ErrorActionPreference='Stop'
if(!(Test-Path -LiteralPath $InspectorPath)){throw "找不到现场检查程序：$InspectorPath"}
$directory=Split-Path -Parent $InspectorPath
$report=Join-Path $directory 'verification-report.html'
Copy-Item -LiteralPath $VerifierPath -Destination (Join-Path $directory 'verify-remediator.ps1') -Force
if(Test-Path -LiteralPath $report){Remove-Item -LiteralPath $report -Force}

$process=Start-Process -FilePath $InspectorPath -ArgumentList @('/no-pause','/no-open') -Wait -PassThru -WindowStyle Hidden
if($process.ExitCode -ne 0 -and $process.ExitCode -ne 5){throw "现场检查程序返回非预期退出码：$($process.ExitCode)"}
if(!(Test-Path -LiteralPath $report)){throw '现场检查程序结束后没有生成报告。'}
$html=[IO.File]::ReadAllText($report)
if(!$html.Contains('六、浏览器密码保存设置逐项明细')){throw '现场检查程序生成的报告缺少浏览器检查。'}

Write-Host 'PASS：现场检查 EXE 等待检查结束并生成完整报告。'
