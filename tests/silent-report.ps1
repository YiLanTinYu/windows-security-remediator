param(
    [Parameter(Mandatory=$true)][string]$RemediatorPath,
    [Parameter(Mandatory=$true)][string]$VerifierPath,
    [Parameter(Mandatory=$true)][string]$InspectorPath
)

$ErrorActionPreference='Stop'
$testDirectory=Join-Path $env:TEMP ("SecurityRemediatorSilentReportTest_{0}" -f [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDirectory | Out-Null

try {
    $is64=[IO.Path]::GetFileName($RemediatorPath) -match 'x64'
    $remediatorName=$(if($is64){'remediator-x64.exe'}else{'remediator.exe'})
    $inspectorName=$(if($is64){'remediator-inspector-x64.exe'}else{'remediator-inspector.exe'})
    $testRemediator=Join-Path $testDirectory $remediatorName
    Copy-Item -LiteralPath $RemediatorPath -Destination $testRemediator
    Copy-Item -LiteralPath $VerifierPath -Destination (Join-Path $testDirectory 'verify-remediator.ps1')
    Copy-Item -LiteralPath $InspectorPath -Destination (Join-Path $testDirectory $inspectorName)

    $process=Start-Process -FilePath $testRemediator -ArgumentList @('/audit','/log-dir',$testDirectory) -Wait -PassThru -WindowStyle Hidden
    if($process.ExitCode -ne 0 -and $process.ExitCode -ne 5){throw "静默审计返回非预期退出码：$($process.ExitCode)"}

    $reports=@(Get-ChildItem -LiteralPath $testDirectory -Filter 'verification-report_*.html' -ErrorAction SilentlyContinue)
    if($reports.Count -ne 1){throw "静默程序结束后应生成一份带 IP/MAC 文件名的报告，实际为 $($reports.Count) 份。"}
    $html=[IO.File]::ReadAllText($reports[0].FullName)
    foreach($required in @(
        '被检查终端IP地址:',
        '一、检查结果汇总（预期与实际对比）',
        '二、防火墙规则逐项明细',
        '三、NetBIOS 网卡逐项明细',
        '四、网络配置注册表记录逐项明细',
        '五、USB 存储设备注册表记录逐项明细',
        '六、浏览器已保存密码逐项明细'
    )){
        if(!$html.Contains($required)){throw "静默报告缺少内容：$required"}
    }
    if(Test-Path -LiteralPath (Join-Path $testDirectory 'verification-report.html')){throw '不应生成旧的固定名称报告。'}

    Write-Host 'PASS：静默程序等待完整 HTML 报告生成，并将报告保存在 EXE 同目录。'
}
finally {
    Remove-Item -LiteralPath $testDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
