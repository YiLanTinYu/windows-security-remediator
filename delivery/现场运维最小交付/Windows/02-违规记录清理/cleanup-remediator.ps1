param([Parameter(Mandatory=$true)][string]$CleanerPath)
$ErrorActionPreference='Stop'
$base=Split-Path -Parent $MyInvocation.MyCommand.Path
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if($identity.IsSystem -or !$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    Write-Host '请以待清理用户本人的提升管理员会话运行，不支持 SYSTEM。' -ForegroundColor Red
    Read-Host '按 Enter 退出';exit 3
}
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$ip='UNKNOWN';$mac='UNKNOWN'
foreach($adapter in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()){
    if($adapter.OperationalStatus -ne 'Up' -or $adapter.NetworkInterfaceType -in @('Loopback','Tunnel')){continue}
    $properties=$adapter.GetIPProperties();if(!$properties.GatewayAddresses.Count){continue}
    $address=$properties.UnicastAddresses|Where-Object {$_.Address.AddressFamily -eq 'InterNetwork'}|Select-Object -First 1
    if($address){$ip=$address.Address.ToString();$mac=$adapter.GetPhysicalAddress().ToString() -replace '(.{2})(?!$)','$1-';break}
}
$report=Join-Path $base ("cleanup-report_{0}_{1}_{2}.html" -f $ip,$mac,$stamp)
$rows=New-Object System.Collections.ArrayList
function E($s){return [Security.SecurityElement]::Escape([string]$s)}
function Row($item,$before,$removed,$after,$status,$note){[void]$rows.Add([pscustomobject]@{Item=$item;Before=$before;Removed=$removed;After=$after;Status=$status;Note=$note})}
function Invoke-IECleanupStore {
    param(
        [Parameter(Mandatory=$true)][string]$CleanerPath,
        [Parameter(Mandatory=$true)][string]$Argument,
        [Parameter(Mandatory=$true)][string]$Label
    )
    try{
        $text=(& $CleanerPath $Argument 2>$null) -join ''
        if($LASTEXITCODE -ne 0){throw "$Label 读取或清理失败，记录清理程序退出码 $LASTEXITCODE"}
        $parts=@($text.Trim() -split '\s+')
        if($parts.Count -ne 3){throw "$Label 返回了无法识别的结果"}
        $before=[int]::Parse($parts[0]);$removed=[int]::Parse($parts[1]);$after=[int]::Parse($parts[2])
        $status=if($Argument -like '/inspect*'){
            if($before -eq 0){'原本无记录'}else{'待确认'}
        }elseif($after -ne 0){'未清空'}elseif($before -eq 0){'原本无记录'}else{'已清空'}
        [pscustomobject]@{Before=$before;Removed=$removed;After=$after;Status=$status;Note='已按当前用户范围复读核对'}
    }catch{
        [pscustomobject]@{Before='?';Removed=0;After='?';Status='失败/需复核';Note=$_.Exception.Message}
    }
}
function SaveReport {
    $body=foreach($r in $rows){'<tr><td>'+ (E $r.Item)+'</td><td>'+(E $r.Before)+'</td><td>'+(E $r.Removed)+'</td><td>'+(E $r.After)+'</td><td>'+(E $r.Status)+'</td><td>'+(E $r.Note)+'</td></tr>'}
    $html='<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>临时清理报告</title><style>body{font-family:Microsoft YaHei;margin:30px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:10px;text-align:left}th{background:#eee}</style><h1>临时清理报告（待现场检查复核）</h1><p>被检查终端IP地址:'+(E $ip)+' MAC地址：'+(E $mac)+'　终端：'+(E $env:COMPUTERNAME)+'　用户：'+(E $identity.Name)+'　时间：'+(E (Get-Date))+'</p><p>本报告记录清理结果；请手动再次运行现场检查工具核对。不会自动启动检查。已接入设备、浏览器同步可能重新产生记录。</p><table><tr><th>清理对象</th><th>清理前数量</th><th>删除数量</th><th>清理后数量</th><th>结果</th><th>说明</th></tr>'+($body -join '')+'</table></html>'
    [IO.File]::WriteAllText($report,$html,(New-Object Text.UTF8Encoding($true)))
}
Write-Host '现场记录清理工具 — 倚栏听雨' -ForegroundColor Cyan
Write-Host ("当前实际用户：{0}；用户目录：{1}" -f $identity.Name,$env:USERPROFILE)
Write-Host '将清理 USBSTOR 历史和当前用户 Edge/Chrome/Firefox 的本地保存密码。IE Storage2 和明确标识为 Microsoft_WinInet_ 的凭据会单独确认后清理。'
Write-Host '请先保存现场检查报告，关闭浏览器，并拔除不需要连接的 USB 存储设备。密码删除不可通过本工具撤销；云端同步密码不在本次清理范围内。'
Write-Host '同时删除本机已保存 Wi-Fi 配置、明确属于无线的 NetworkList 历史并禁用无线网卡；有线历史保留，未知类型列出供人工确认。当前无线连接将断开，请先确认有线网络可用。'
if((Read-Host '确认上述用户和范围后，输入 yes 继续') -cne 'yes'){exit 2}
# Confirm the report directory is writable before changing any records.
Row '清理任务' '-' '-' '-' '执行中' '若任务中断，请以现场复检结果为准'
SaveReport
$rows.Clear()
$usbCleaner=$CleanerPath
if([Environment]::Is64BitOperatingSystem){
    $nativeCleaner=Join-Path $base 'record-cleaner-x64.exe'
    if(Test-Path -LiteralPath $nativeCleaner){$CleanerPath=$nativeCleaner;$usbCleaner=$nativeCleaner}
    else{$usbCleaner=$null}
}
$inspector=$CleanerPath
foreach($browser in @(@('Edge','msedge','Microsoft\Edge\User Data'),@('Chrome','chrome','Google\Chrome\User Data'))){
    $name=$browser[0];$root=Join-Path $env:LOCALAPPDATA $browser[2]
    if(Get-Process -Name $browser[1] -ErrorAction SilentlyContinue){Row $name '?' 0 '?' '跳过' '浏览器仍在运行，请关闭后重试';SaveReport;continue}
    if(!(Test-Path -LiteralPath $root)){Row $name 0 0 0 '未发现' '当前用户标准配置目录不存在';continue}
    foreach($profile in (Get-ChildItem -LiteralPath $root -Directory)){
        foreach($dbName in @('Login Data','Login Data For Account')){
            $db=Join-Path $profile.FullName $dbName;if(!(Test-Path -LiteralPath $db)){continue}
            $item="$name / $($profile.Name) / $dbName";$before='?';$removed=0
            try{
                if(!(Test-Path -LiteralPath $inspector)){throw '缺少记录清理 EXE，无法验证数量'}
                $beforeText=(& $inspector /count-chromium-logins $db) -join '';if($LASTEXITCODE -ne 0){throw '无法读取清理前数量'};$before=[long]::Parse($beforeText)
                if($before -gt 0){$removedText=(& $CleanerPath /clear-chromium $db) -join '';if($LASTEXITCODE -ne 0){throw '密码库占用或格式不支持，删除失败'};$removed=[long]::Parse($removedText)}
                $afterText=(& $inspector /count-chromium-logins $db) -join '';if($LASTEXITCODE -ne 0){throw '删除后无法复读'};$after=[long]::Parse($afterText)
                Row $item $before $removed $after $(if($after -ne 0){'未清空'}elseif($before -eq 0){'原本无记录'}else{'已清空'}) '仅删除包含密码的登录记录，保留其他浏览器数据'
            }catch{Row $item $before $removed '?' '失败/需复核' $_.Exception.Message}
            SaveReport
        }
    }
}
$firefox=Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles'
if(Get-Process firefox -ErrorAction SilentlyContinue){Row 'Firefox' '?' 0 '?' '跳过' '浏览器仍在运行'}
elseif(Test-Path -LiteralPath $firefox){foreach($profile in (Get-ChildItem -LiteralPath $firefox -Directory)){
    foreach($loginFile in @('logins.json','logins-backup.json')){
    $file=Join-Path $profile.FullName $loginFile;if(!(Test-Path -LiteralPath $file)){continue};$before='?'
    try{$data=[IO.File]::ReadAllText($file)|ConvertFrom-Json;if($null -eq $data.logins){throw '无法识别密码文件'};$before=@($data.logins).Count
        if($before -gt 0){Remove-Item -LiteralPath $file -Force -ErrorAction Stop}
        $after=0;if(Test-Path -LiteralPath $file){$remaining=[IO.File]::ReadAllText($file)|ConvertFrom-Json -ErrorAction Stop;$after=@($remaining.logins).Count}
        Row "Firefox / $($profile.Name) / $loginFile" $before ($before-$after) $after $(if($after -gt 0){'未清空'}elseif($before -eq 0){'原本无记录'}else{'已清空'}) '只处理本地登录记录文件，保留密钥及其他浏览器数据'
    }catch{Row "Firefox / $($profile.Name) / $loginFile" $before 0 '?' '失败/需复核' $_.Exception.Message};SaveReport
    }
}}
else{Row 'Firefox' 0 0 0 '未发现' '当前用户标准配置目录不存在'}
$ieStorage=Invoke-IECleanupStore -CleanerPath $CleanerPath -Argument '/inspect-ie-storage2' -Label 'IE Storage2'
$ieWinInet=Invoke-IECleanupStore -CleanerPath $CleanerPath -Argument '/inspect-ie-wininet' -Label 'IE WinInet 凭据'
$ieAutomaticCount=0
foreach($state in @($ieStorage,$ieWinInet)){if($state.Before -is [int]){$ieAutomaticCount+=$state.Before}}
$confirmIE=$false
if($ieAutomaticCount -gt 0){
    Write-Host ("检测到 {0} 条可明确归属于当前用户 IE/WinInet 的记录。不会删除其他 Windows 凭据。" -f $ieAutomaticCount) -ForegroundColor Yellow
    $confirmIE=(Read-Host '如需清理这些 IE 记录，请再次输入 yes') -ceq 'yes'
}
foreach($store in @(
    [pscustomobject]@{Label='Internet Explorer / Storage2';Inspect=$ieStorage;Clear='/clear-ie-storage2'},
    [pscustomobject]@{Label='Internet Explorer / WinInet';Inspect=$ieWinInet;Clear='/clear-ie-wininet'}
)){
    if($store.Inspect.Status -eq '失败/需复核'){
        Row $store.Label $store.Inspect.Before 0 $store.Inspect.After $store.Inspect.Status $store.Inspect.Note
    }elseif($store.Inspect.Before -eq 0){
        Row $store.Label 0 0 0 '原本无记录' '当前用户未发现该类 IE 保存密码记录'
    }elseif(!$confirmIE){
        Row $store.Label $store.Inspect.Before 0 $store.Inspect.After '跳过' '用户未进行第二次确认，未删除记录'
    }else{
        $result=Invoke-IECleanupStore -CleanerPath $CleanerPath -Argument $store.Clear -Label $store.Label
        Row $store.Label $result.Before $result.Removed $result.After $result.Status $result.Note
    }
    SaveReport
}
try{
    $webText=(& $CleanerPath /count-ie-web-credentials 2>$null) -join ''
    if($LASTEXITCODE -ne 0){throw "Windows Web 凭据读取失败，记录清理程序退出码 $LASTEXITCODE"}
    $webCount=[int]::Parse($webText.Trim())
    if($webCount -eq 0){Row 'Internet Explorer / Windows Web 凭据' 0 0 0 '原本无记录' '当前用户未发现 Web 凭据'}
    else{Row 'Internet Explorer / Windows Web 凭据' $webCount 0 $webCount '需人工处理' 'Web 凭据无法可靠区分 IE 与其他应用；为避免误删，请在 Windows 凭据管理器中逐项确认'}
}catch{Row 'Internet Explorer / Windows Web 凭据' '?' 0 '?' '失败/需复核' $_.Exception.Message}
Row '360 / 世界之窗及其他未适配浏览器' '?' 0 '?' '需人工处理' '请在各浏览器密码管理中清空；不表示已全部清空'
$usb='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR'
try{
    if(!$usbCleaner){Row 'USBSTOR' '?' 0 '?' '失败/需复核' '64 位 Windows 缺少 record-cleaner-x64.exe，为避免 WOW64 设备管理失败，未执行 USB 清理'}
    elseif(!(Test-Path -LiteralPath $usb)){Row 'USBSTOR' 0 0 0 '未发现' '无历史记录'}
    else{foreach($device in (Get-ChildItem -LiteralPath $usb)){foreach($instance in (Get-ChildItem -LiteralPath $device.PSPath)){
        $item="USBSTOR / $($device.PSChildName) / $($instance.PSChildName)";$after='?'
        try{
            $id="USBSTOR\$($device.PSChildName)\$($instance.PSChildName)"
            & $usbCleaner /remove-usb-history $id|Out-Null;$code=$LASTEXITCODE
            try{$null=Get-Item -LiteralPath $instance.PSPath -ErrorAction Stop;$after=1}catch [System.Management.Automation.ItemNotFoundException]{$after=0}
            if($code -eq 170){Row $item 1 0 $after '跳过' '设备仍连接，请安全拔出后重试'}
            elseif($code -eq 3010){Row $item 1 $(if($after -eq 0){1}else{0}) $after '待重启复核' 'Windows 要求稍后重启，本程序不自动重启'}
            elseif($code -ne 0){Row $item 1 $(if($after -eq 0){1}else{0}) $after '失败/需复核' ("设备管理接口返回错误 {0}，请结合复检确认" -f $code)}
            elseif($after -eq 0){Row $item 1 1 0 '已清空' 'Windows 已移除断开设备的注册信息，复读确认实例不存在；驱动包保留'}
            else{Row $item 1 0 $after '未清空' '接口已返回，但实例仍存在或被重新创建'}
        }catch{Row $item 1 0 $after '失败/需复核' $_.Exception.Message};SaveReport
    }}}
}catch{Row 'USBSTOR' '?' 0 '?' '失败/需复核' $_.Exception.Message}
try{
    . (Join-Path $base 'wireless-remediator.ps1')
    foreach($entry in @(Invoke-WirelessCleanup)){Row $entry.Item $entry.Before $entry.Removed $entry.After $entry.Status $entry.Note;SaveReport}
}catch{Row '无线网络清理' '?' 0 '?' '失败/需复核' $_.Exception.Message}
SaveReport
Write-Host "已生成临时报告：$report" -ForegroundColor Cyan
Write-Host '请再次运行现场检查工具，将新报告与本报告逐项对照。'
Start-Process -FilePath $report
Read-Host '按 Enter 退出'
if(@($rows|Where-Object {$_.Status -in @('失败/需复核','跳过','未清空','需人工处理','待重启复核')}).Count){exit 1}else{exit 0}
