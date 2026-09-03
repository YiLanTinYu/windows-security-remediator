param(
    [Parameter(Mandatory=$true)]
    [string]$VerifierPath
)

$ErrorActionPreference='Stop'
$report=Join-Path (Split-Path -Parent $VerifierPath) 'verification-report.html'
if(Test-Path -LiteralPath $report){Remove-Item -LiteralPath $report -Force}

$process=Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$VerifierPath,'-Interactive') -Wait -PassThru -WindowStyle Hidden
if(!(Test-Path -LiteralPath $report)){throw '现场检查未生成 HTML 报告。'}
$html=[IO.File]::ReadAllText($report)

foreach($required in @('六、浏览器密码保存设置逐项明细','Microsoft Edge','Google Chrome','Mozilla Firefox','Internet Explorer','只检查安装状态和设置，不读取或导出已保存密码')){
    if(!$html.Contains($required)){throw "报告缺少现场检查内容：$required"}
}
foreach($required in @('<th>检查项目</th>','Microsoft Edge</td><td>安装状态</td>','Google Chrome</td><td>安装状态</td>','Mozilla Firefox</td><td>安装状态</td>','Internet Explorer</td><td>安装状态</td>')){
    if(!$html.Contains($required)){throw "报告没有把浏览器安装状态单独列出：$required"}
}
foreach($browser in @('Microsoft Edge','Google Chrome','Internet Explorer')){
    if($html -notmatch ([regex]::Escape("$browser</td><td>安装状态</td>") + '.*?<td>已安装</td>')){
        throw "已安装的浏览器被错误识别：$browser"
    }
}
if($html -notmatch ([regex]::Escape('Mozilla Firefox</td><td>安装状态</td>') + '.*?<td>未安装</td>.*?<td class="na">不适用</td>')){
    throw '未安装的 Firefox 没有显示为“未安装/不适用”。'
}
foreach($forbidden in @('Login Data','logins.json','Web Data')){
    if($html.Contains($forbidden)){throw "报告包含不应访问的密码存储标识：$forbidden"}
}
if($process.ExitCode -ne 0 -and $process.ExitCode -ne 5){throw "现场检查返回非预期退出码：$($process.ExitCode)"}

Write-Host 'PASS：现场报告包含浏览器密码保存设置，且未引用密码存储文件。'
