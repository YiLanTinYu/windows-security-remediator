$ErrorActionPreference = 'Continue'
$base = Split-Path -Parent $MyInvocation.MyCommand.Path
$report = Join-Path $base 'verification-report.html'
$legacyLog = Join-Path $base 'verification.log'
$details=New-Object System.Collections.ArrayList
function W([string]$s) { [void]$script:details.Add($s) }
$summary=@()
$firewallRows=@();$netbiosRows=@();$networkRows=@();$usbRows=@()
function S([string]$item,[string]$expected,[string]$actual,[string]$conclusion) {
    $script:summary+=New-Object PSObject -Property @{Item=$item;Expected=$expected;Actual=$actual;Conclusion=$conclusion}
}
function EncodeHtml($value) {
    if($null -eq $value){return ''}
    return ([string]$value).Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;')
}
function C([string]$conclusion) { if($conclusion -eq '通过'){'pass'}elseif($conclusion -eq '异常'){'fail'}else{'review'} }
W ('=' * 60); W ("SecurityRemediator 验证开始：{0}" -f (Get-Date)); W ""
W '[1] 检查 Server 文件共享服务（LanmanServer）'
sc.exe query LanmanServer 2>&1 | ForEach-Object { W $_ }
sc.exe qc LanmanServer 2>&1 | ForEach-Object { W $_ }
try {
    $service=Get-Service LanmanServer -ErrorAction Stop; $start=(Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer' -Name Start -ErrorAction Stop).Start
    $actual="状态={0}，启动类型={1}" -f $(if($service.Status -eq 'Stopped'){'已停止'}else{[string]$service.Status}),$(if($start -eq 4){'已禁用'}else{"Start=$start"})
    W ("结果：{0}" -f $actual); S 'Server 文件共享服务' '已停止、已禁用' $actual $(if($service.Status -eq 'Stopped' -and $start -eq 4){'通过'}else{'异常'})
} catch { W '结果：无法读取 Server 服务。'; S 'Server 文件共享服务' '已停止、已禁用' '无法读取' '异常' }
W ''
W '[2] 检查远程桌面服务（TermService）'
sc.exe query TermService 2>&1 | ForEach-Object { W $_ }
sc.exe qc TermService 2>&1 | ForEach-Object { W $_ }
try {
    $service=Get-Service TermService -ErrorAction Stop; $start=(Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService' -Name Start -ErrorAction Stop).Start
    $actual="状态={0}，启动类型={1}" -f $(if($service.Status -eq 'Stopped'){'已停止'}else{[string]$service.Status}),$(if($start -eq 4){'已禁用'}else{"Start=$start"})
    W ("结果：{0}" -f $actual); S '远程桌面服务' '已停止、已禁用' $actual $(if($service.Status -eq 'Stopped' -and $start -eq 4){'通过'}else{'异常'})
} catch { W '结果：无法读取远程桌面服务。'; S '远程桌面服务' '已停止、已禁用' '无法读取' '异常' }
W ''
W '[3] 检查远程桌面注册表配置'
reg.exe query 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections 2>&1 | ForEach-Object { W $_ }
try {$rdp=(Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections;S '远程桌面连接策略' '禁止连接（值为1）' $(if($rdp -eq 1){'已禁止连接（值为1）'}else{"当前值=$rdp"}) $(if($rdp -eq 1){'通过'}else{'异常'})}catch{S '远程桌面连接策略' '禁止连接（值为1）' '无法读取' '异常'}
W '预期：fDenyTSConnections 为 0x1。'; W ''
W '[4] 检查防火墙规则'
$ruleNames=@('TCP-22','TCP-135','TCP-136','UDP-136','UDP-137','UDP-138','TCP-139','TCP-445','TCP-3389','UDP-3389')
$firewallPassed=0;$firewallMissing=0;$firewallDuplicateKinds=0;$firewallDuplicateRules=0
foreach($tag in $ruleNames){
    $name='SecurityRemediator - Block '+$tag
    $output=@(netsh.exe advfirewall firewall show rule name="$name" verbose 2>&1)
    $count=@($output|Select-String -SimpleMatch $name).Count
    if($count -eq 1){$firewallPassed++;$actual='1条';$conclusion='通过';W ("{0}：1 条，通过" -f $tag)}
    elseif($count -eq 0){$firewallMissing++;$actual='0条，缺失';$conclusion='异常';W ("{0}：0 条，缺失" -f $tag)}
    else{$firewallDuplicateKinds++;$firewallDuplicateRules+=($count-1);$actual=("{0}条，多余{1}条" -f $count,($count-1));$conclusion='异常';W ("{0}：{1} 条，发现 {2} 条重复" -f $tag,$count,($count-1))}
    S ("防火墙规则 {0}" -f $tag) '恰好保留1条' $actual $conclusion
    $firewallRows+=New-Object PSObject -Property @{Rule=$tag;Expected='1条';Actual=$count;Conclusion=$conclusion}
}
W '预期：每个 SecurityRemediator 规则均为 1 条。'; W ''
W '[5] 检查 NetBIOS 配置'
reg.exe query 'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' /s /v NetbiosOptions 2>&1 | ForEach-Object { W $_ }
try{$interfaces=Get-ChildItem -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction Stop;$netbiosTotal=0;$netbiosPassed=0;foreach($interface in $interfaces){$netbiosTotal++;$option=(Get-ItemProperty -LiteralPath $interface.PSPath -Name NetbiosOptions -ErrorAction Stop).NetbiosOptions;$conclusion=$(if($option -eq 2){$netbiosPassed++;'通过'}else{'异常'});$netbiosRows+=New-Object PSObject -Property @{Interface=$interface.PSChildName;Expected=2;Actual=$option;Conclusion=$conclusion}};S 'NetBIOS 配置汇总' '所有网卡均禁用（值为2）' ("{0}/{1}个网卡为禁用" -f $netbiosPassed,$netbiosTotal) $(if($netbiosTotal -gt 0 -and $netbiosPassed -eq $netbiosTotal){'通过'}else{'异常'})}catch{S 'NetBIOS 配置汇总' '所有网卡均禁用（值为2）' '无法完整读取' '异常'}
W '预期：各网卡 NetbiosOptions 为 0x2。'; W ''
W '[6] 检查本机 TCP 监听（仅供参考）'
$listeners=@(netstat.exe -ano | Select-String ':135|:139|:445|:3389');$listeners|ForEach-Object { W $_.Line }
S '端口外部连通性' '其他电脑无法连接目标端口' ("本机发现{0}条相关监听记录" -f $listeners.Count) '需复核'
W '注意：最终应从另一台电脑测试入站连接。'; W ''

function V($value) { if ($null -eq $value -or [string]::IsNullOrEmpty([string]$value)) { '-' } else { ([string]$value).Replace("`t",' ').Replace("`r",' ').Replace("`n",' ') } }
function RegistryTime($bytes) {
    if ($null -eq $bytes -or $bytes.Count -lt 16) { return '-' }
    try {
        $year=[BitConverter]::ToUInt16($bytes,0); $month=[BitConverter]::ToUInt16($bytes,2); $day=[BitConverter]::ToUInt16($bytes,6)
        $hour=[BitConverter]::ToUInt16($bytes,8); $minute=[BitConverter]::ToUInt16($bytes,10); $second=[BitConverter]::ToUInt16($bytes,12)
        return (Get-Date -Year $year -Month $month -Day $day -Hour $hour -Minute $minute -Second $second -Format 'yyyy-MM-dd HH:mm:ss')
    } catch { return '-' }
}
function NetworkCategory($value) { if ($value -eq 0) {'公用'} elseif ($value -eq 1) {'专用'} elseif ($value -eq 2) {'域'} else {V $value} }

W '[7] 网络配置注册表记录（NetworkList\Profiles）'
W "序号`t配置文件 GUID`t网络名称`t描述`t类别`t创建时间`t最后连接时间"
try {
    $profiles=Get-ChildItem -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles' -ErrorAction Stop
    $index=0
    foreach($profile in $profiles) {
        $index++; $item=Get-ItemProperty -LiteralPath $profile.PSPath -ErrorAction Stop
        W ("{0}`t{1}`t{2}`t{3}`t{4}`t{5}`t{6}" -f $index,(V $profile.PSChildName),(V $item.ProfileName),(V $item.Description),(NetworkCategory $item.Category),(RegistryTime $item.DateCreated),(RegistryTime $item.DateLastConnected))
        $networkRows+=New-Object PSObject -Property @{Index=$index;Guid=(V $profile.PSChildName);Name=(V $item.ProfileName);Description=(V $item.Description);Category=(NetworkCategory $item.Category);Created=(RegistryTime $item.DateCreated);Connected=(RegistryTime $item.DateLastConnected)}
    }
    if($index -eq 0){W "-`t未发现网络配置记录"};S '网络配置记录' '能够正常读取' ("读取成功，共{0}条" -f $index) '通过'
} catch { W ("错误`t无法读取 NetworkList\Profiles：{0}" -f $_.Exception.Message);S '网络配置记录' '能够正常读取' '读取失败' '异常' }
W ''

W '[8] USB 存储设备注册表记录（USBSTOR）'
W "序号`t设备类型`t实例 ID/序列号`t友好名称`t设备描述`t厂商"
try {
    $devices=Get-ChildItem -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction Stop
    $index=0
    foreach($device in $devices) {
        foreach($instance in (Get-ChildItem -LiteralPath $device.PSPath -ErrorAction Stop)) {
            $index++; $item=Get-ItemProperty -LiteralPath $instance.PSPath -ErrorAction Stop
            W ("{0}`t{1}`t{2}`t{3}`t{4}`t{5}" -f $index,(V $device.PSChildName),(V $instance.PSChildName),(V $item.FriendlyName),(V $item.DeviceDesc),(V $item.Mfg))
            $usbRows+=New-Object PSObject -Property @{Index=$index;Type=(V $device.PSChildName);Instance=(V $instance.PSChildName);Name=(V $item.FriendlyName);Description=(V $item.DeviceDesc);Manufacturer=(V $item.Mfg)}
        }
    }
    if($index -eq 0){W "-`t未发现 USB 存储设备记录"};S 'USB 存储设备记录' '能够正常读取' ("读取成功，共{0}条" -f $index) '通过'
} catch { W ("错误`t无法读取 USBSTOR：{0}" -f $_.Exception.Message);S 'USB 存储设备记录' '能够正常读取' '读取失败' '异常' }
W ''

$passed=@($summary|Where-Object {$_.Conclusion -eq '通过'}).Count;$failed=@($summary|Where-Object {$_.Conclusion -eq '异常'}).Count;$review=@($summary|Where-Object {$_.Conclusion -eq '需复核'}).Count
$finished=Get-Date
W ("验证结束：{0}" -f $finished)
if($failed -eq 0){$overallClass='pass';$overallText='本机配置检查未发现异常；端口是否真正无法从外部访问，仍需从另一台电脑测试。'}else{$overallClass='fail';$overallText='存在未达到预期的项目，请先处理“异常”项，再重新验证。'}

$html=New-Object System.Text.StringBuilder
[void]$html.AppendLine('<!doctype html>')
[void]$html.AppendLine('<html lang="zh-CN"><head><meta charset="utf-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><title>高危端口阻断验证报告</title>')
[void]$html.AppendLine('<style>body{margin:0;background:#f3f5f7;color:#202124;font-family:"Microsoft YaHei",Arial,sans-serif;font-size:14px;line-height:1.6}.wrap{max-width:1200px;margin:24px auto;padding:0 18px}.header,.card{background:#fff;border:1px solid #dfe3e8;border-radius:6px;margin-bottom:18px;padding:20px}.header h1{margin:0 0 8px;font-size:24px}.meta{color:#687078}.banner{border-left:6px solid #2e7d32}.banner.fail{border-left-color:#c62828}.counts{font-size:18px;margin:8px 0}.pass{color:#1b5e20;font-weight:bold}.fail{color:#b71c1c;font-weight:bold}.review{color:#9a6700;font-weight:bold}h2{font-size:19px;margin:0 0 12px;padding-bottom:8px;border-bottom:2px solid #e7eaed}table{width:100%;border-collapse:collapse;table-layout:auto}th,td{border:1px solid #d9dde2;padding:8px 10px;text-align:left;vertical-align:top;word-break:break-all}th{background:#eef2f5;white-space:nowrap}.scroll{overflow-x:auto}.note{background:#fff8e1;border:1px solid #f0d98a;padding:10px 12px;margin-top:12px}pre{white-space:pre-wrap;word-wrap:break-word;background:#f7f8fa;border:1px solid #dfe3e8;padding:14px;max-height:520px;overflow:auto}.small{font-size:12px;color:#687078}</style></head><body><div class="wrap">')
[void]$html.AppendLine(('<div class="header banner {0}"><h1>高危端口阻断验证报告</h1><div class="meta">计算机：{1}　验证时间：{2}</div><div class="counts">通过 <span class="pass">{3}</span> 项　异常 <span class="fail">{4}</span> 项　需人工复核 <span class="review">{5}</span> 项</div><div>{6}</div></div>' -f $overallClass,(EncodeHtml $env:COMPUTERNAME),(EncodeHtml $finished.ToString('yyyy-MM-dd HH:mm:ss')),$passed,$failed,$review,(EncodeHtml $overallText)))

[void]$html.AppendLine('<div class="card"><h2>一、检查结果汇总（预期与实际对比）</h2><div class="scroll"><table><thead><tr><th>序号</th><th>检查项目</th><th>预期结果</th><th>实际检查结果</th><th>结论</th></tr></thead><tbody>')
$i=0;foreach($row in $summary){$i++;[void]$html.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td class="{4}">{5}</td></tr>' -f $i,(EncodeHtml $row.Item),(EncodeHtml $row.Expected),(EncodeHtml $row.Actual),(C $row.Conclusion),(EncodeHtml $row.Conclusion)))}
[void]$html.AppendLine('</tbody></table></div><div class="note">说明：“需复核”不代表失败。端口能否从其他电脑访问，必须在另一台电脑上进行连接测试。</div></div>')

[void]$html.AppendLine('<div class="card"><h2>二、防火墙规则逐项明细</h2><div class="scroll"><table><thead><tr><th>序号</th><th>规则</th><th>预期结果</th><th>实际数量</th><th>结论</th></tr></thead><tbody>')
$i=0;foreach($row in $firewallRows){$i++;[void]$html.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}条</td><td class="{4}">{5}</td></tr>' -f $i,(EncodeHtml $row.Rule),(EncodeHtml $row.Expected),(EncodeHtml $row.Actual),(C $row.Conclusion),(EncodeHtml $row.Conclusion)))}
[void]$html.AppendLine('</tbody></table></div></div>')

[void]$html.AppendLine('<div class="card"><h2>三、NetBIOS 网卡逐项明细</h2><div class="scroll"><table><thead><tr><th>序号</th><th>网卡接口</th><th>预期值</th><th>实际值</th><th>结论</th></tr></thead><tbody>')
$i=0;foreach($row in $netbiosRows){$i++;[void]$html.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}（禁用）</td><td>{3}</td><td class="{4}">{5}</td></tr>' -f $i,(EncodeHtml $row.Interface),(EncodeHtml $row.Expected),(EncodeHtml $row.Actual),(C $row.Conclusion),(EncodeHtml $row.Conclusion)))}
if($netbiosRows.Count -eq 0){[void]$html.AppendLine('<tr><td colspan="5" class="fail">未读取到网卡接口记录</td></tr>')}
[void]$html.AppendLine('</tbody></table></div></div>')

[void]$html.AppendLine('<div class="card"><h2>四、网络配置注册表记录逐项明细</h2><div class="scroll"><table><thead><tr><th>序号</th><th>配置文件 GUID</th><th>网络名称</th><th>描述</th><th>类别</th><th>创建时间</th><th>最后连接时间</th></tr></thead><tbody>')
foreach($row in $networkRows){[void]$html.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f $row.Index,(EncodeHtml $row.Guid),(EncodeHtml $row.Name),(EncodeHtml $row.Description),(EncodeHtml $row.Category),(EncodeHtml $row.Created),(EncodeHtml $row.Connected)))}
if($networkRows.Count -eq 0){[void]$html.AppendLine('<tr><td colspan="7">未发现网络配置记录</td></tr>')}
[void]$html.AppendLine('</tbody></table></div></div>')

[void]$html.AppendLine('<div class="card"><h2>五、USB 存储设备注册表记录逐项明细</h2><div class="scroll"><table><thead><tr><th>序号</th><th>设备类型</th><th>实例 ID/序列号</th><th>友好名称</th><th>设备描述</th><th>厂商</th></tr></thead><tbody>')
foreach($row in $usbRows){[void]$html.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f $row.Index,(EncodeHtml $row.Type),(EncodeHtml $row.Instance),(EncodeHtml $row.Name),(EncodeHtml $row.Description),(EncodeHtml $row.Manufacturer)))}
if($usbRows.Count -eq 0){[void]$html.AppendLine('<tr><td colspan="6">未发现 USB 存储设备记录</td></tr>')}
[void]$html.AppendLine('</tbody></table></div></div>')

[void]$html.AppendLine(('<div class="card"><h2>六、原始检查信息</h2><p class="small">用于管理员进一步排查，普通使用者优先查看前面的汇总和逐项明细。</p><pre>{0}</pre></div>' -f (EncodeHtml ($details -join "`r`n"))))
[void]$html.AppendLine('</div></body></html>')
$utf8=New-Object System.Text.UTF8Encoding($true)
[System.IO.File]::WriteAllText($report,$html.ToString(),$utf8)
if(Test-Path -LiteralPath $legacyLog){Remove-Item -LiteralPath $legacyLog -Force}
Write-Host "验证完成，HTML 报告：$report"
