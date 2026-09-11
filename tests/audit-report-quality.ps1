param([Parameter(Mandatory=$true)][string]$Inspector)
$ErrorActionPreference='Stop'
$root=Join-Path $env:TEMP ('sr-audit-quality-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root|Out-Null
try {
    $exe=Join-Path $root 'inspector.exe'
    Copy-Item -LiteralPath $Inspector -Destination $exe
    $p=Start-Process -FilePath $exe -ArgumentList '/audit-only','/no-open','/no-pause' -WorkingDirectory $root -Wait -PassThru
    if($p.ExitCode -notin 0,5){throw "检查失败：$($p.ExitCode)"}
    $report=Get-Content -Raw -LiteralPath (Get-ChildItem $root -Filter 'verification-report_*.json'|Select-Object -First 1).FullName|ConvertFrom-Json
    if($report.ip -eq 'UNKNOWN' -or $report.mac -eq 'UNKNOWN'){throw '有效联网终端不应缺少 IP/MAC'}
    if($report.adapter -match '环回|loopback|KM-TEST|Virtual|Host-Only|虚拟'){throw "主用网卡误选为测试或虚拟适配器：$($report.adapter)"}
    if(@($report.summary|Where-Object {$_.actual -match '^状态=\d|启动类型=\d'}).Count){throw '服务状态仍输出原始数字'}
    if(@($report.summary|Where-Object {$_.item -match '^无线网卡 / .*(WFP|Filter Driver|QoS Packet Scheduler)'}).Count){throw '协议或过滤器仍被误报为无线网卡'}
    $history=$report.summary|Where-Object item -eq '网络配置记录'
    if($history.actual -match '无线[1-9]\d*条' -and $history.conclusion -eq '通过'){throw '存在无线历史却判定通过'}
    if(-not ($report.details.title -contains '相关端口监听逐项明细')){throw '缺少端口监听明细'}
    if(-not ($report.details.title -contains '已保存 Wi-Fi 配置逐项明细')){throw '缺少 Wi-Fi 配置明细'}
    Write-Host 'PASS: 终端身份、服务文字、无线分类、历史结论和明细符合要求。'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
