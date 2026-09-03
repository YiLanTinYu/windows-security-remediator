param(
    [Parameter(Mandatory=$true)]
    [string]$VerifierPath
)

$ErrorActionPreference='Stop'
$reportDirectory=Split-Path -Parent $VerifierPath
Get-ChildItem -LiteralPath $reportDirectory -Filter 'verification-report*.html' -ErrorAction SilentlyContinue | Remove-Item -Force

$network=Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -and $_.IPv4Address} | Select-Object -First 1
if(!$network){throw '测试机没有带 IPv4 默认网关的活动网卡。'}
$expectedIp=[string]$network.IPv4Address.IPAddress
$adapter=Get-NetAdapter -InterfaceIndex $network.InterfaceIndex -ErrorAction Stop
$expectedMac=([string]$adapter.MacAddress).ToUpperInvariant()
$report=Join-Path $reportDirectory ("verification-report_{0}_{1}.html" -f $expectedIp,$expectedMac)

$process=Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$VerifierPath,'-Interactive') -Wait -PassThru -WindowStyle Hidden
if(!(Test-Path -LiteralPath $report)){throw '现场检查未生成 HTML 报告。'}
$html=[IO.File]::ReadAllText($report)

$identityText="被检查终端IP地址:$expectedIp  MAC地址：$expectedMac"
if(!$html.Contains($identityText)){throw "报告首页缺少终端 IP/MAC：$identityText"}

foreach($required in @('六、浏览器已保存密码逐项明细','Microsoft Edge','Google Chrome','Mozilla Firefox','Internet Explorer','已保存密码','只判断是否存在已保存密码并统计条目数量','不解密、不显示、不导出密码')){
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

Write-Host 'PASS：报告文件名和首页包含同一终端 IP/MAC，且浏览器密码检查完整。'
