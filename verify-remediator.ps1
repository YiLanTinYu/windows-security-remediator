param([switch]$Interactive,[switch]$ExitWithStatus,[string]$InspectorPath)
$ErrorActionPreference = 'Continue'
$base = Split-Path -Parent $MyInvocation.MyCommand.Path
function GetTerminalNetworkIdentity {
    try {
        if(Get-Command Get-NetIPConfiguration -ErrorAction SilentlyContinue){
            $configuration=Get-NetIPConfiguration -ErrorAction SilentlyContinue|Where-Object {$_.IPv4DefaultGateway -and $_.IPv4Address}|Select-Object -First 1
            if($configuration){
                $adapter=Get-NetAdapter -InterfaceIndex $configuration.InterfaceIndex -ErrorAction SilentlyContinue
                $ip=[string]$configuration.IPv4Address.IPAddress;$mac=$(if($adapter){([string]$adapter.MacAddress).ToUpperInvariant()}else{'UNKNOWN'})
                if($ip){return New-Object PSObject -Property @{IP=$ip;MAC=$mac;Interface=[string]$configuration.InterfaceAlias}}
            }
        }
    }catch{}
    try {
        foreach($adapter in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()){
            if($adapter.OperationalStatus -ne [Net.NetworkInformation.OperationalStatus]::Up){continue}
            if($adapter.NetworkInterfaceType -eq [Net.NetworkInformation.NetworkInterfaceType]::Loopback -or $adapter.NetworkInterfaceType -eq [Net.NetworkInformation.NetworkInterfaceType]::Tunnel){continue}
            $properties=$adapter.GetIPProperties();$hasGateway=$false;foreach($gateway in $properties.GatewayAddresses){if($gateway.Address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork){$hasGateway=$true;break}};if(!$hasGateway){continue}
            foreach($address in $properties.UnicastAddresses){if($address.Address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork){$raw=$adapter.GetPhysicalAddress().ToString().ToUpperInvariant();$mac=$(if($raw){$raw -replace '(.{2})(?!$)','$1-'}else{'UNKNOWN'});return New-Object PSObject -Property @{IP=$address.Address.ToString();MAC=$mac;Interface=$adapter.Name}}}
        }
    }catch{}
    return New-Object PSObject -Property @{IP='UNKNOWN';MAC='UNKNOWN';Interface='未识别'}
}
$terminalNetwork=GetTerminalNetworkIdentity
$safeIp=([string]$terminalNetwork.IP) -replace '[^0-9A-Za-z_.-]','-';$safeMac=([string]$terminalNetwork.MAC) -replace '[^0-9A-Za-z_.-]','-'
$report = Join-Path $base ("verification-report_{0}_{1}_{2}.html" -f $safeIp,$safeMac,(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$legacyLog = Join-Path $base 'verification.log'
$details=New-Object System.Collections.ArrayList
function W([string]$s) { [void]$script:details.Add($s) }
$summary=@()
$firewallRows=@();$netbiosRows=@();$networkRows=@();$usbRows=@();$browserRows=@()
function S([string]$item,[string]$expected,[string]$actual,[string]$conclusion) {
    $script:summary+=New-Object PSObject -Property @{Item=$item;Expected=$expected;Actual=$actual;Conclusion=$conclusion}
}
function EncodeHtml($value) {
    if($null -eq $value){return ''}
    return ([string]$value).Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;')
}
function C([string]$conclusion) { if($conclusion -eq '通过'){'pass'}elseif($conclusion -eq '异常'){'fail'}elseif($conclusion -eq '不适用'){'na'}elseif($conclusion -eq '已识别'){'info'}else{'review'} }
function ShowStep([string]$text) { if($Interactive){Write-Host ("[检查] {0}" -f $text) -ForegroundColor Cyan} }
W ('=' * 60); W ("SecurityRemediator 验证开始：{0}" -f (Get-Date)); W ""
W ("被检查终端IP地址:{0}  MAC地址：{1}  主用网卡：{2}" -f $terminalNetwork.IP,$terminalNetwork.MAC,$terminalNetwork.Interface);W ''
ShowStep 'Server 文件共享服务'
W '[1] 检查 Server 文件共享服务（LanmanServer）'
sc.exe query LanmanServer 2>&1 | ForEach-Object { W $_ }
sc.exe qc LanmanServer 2>&1 | ForEach-Object { W $_ }
try {
    $service=Get-Service LanmanServer -ErrorAction Stop; $start=(Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer' -Name Start -ErrorAction Stop).Start
    $actual="状态={0}，启动类型={1}" -f $(if($service.Status -eq 'Stopped'){'已停止'}else{[string]$service.Status}),$(if($start -eq 4){'已禁用'}else{"Start=$start"})
    W ("结果：{0}" -f $actual); S 'Server 文件共享服务' '已停止、已禁用' $actual $(if($service.Status -eq 'Stopped' -and $start -eq 4){'通过'}else{'异常'})
} catch { W '结果：无法读取 Server 服务。'; S 'Server 文件共享服务' '已停止、已禁用' '无法读取' '异常' }
W ''
ShowStep '远程桌面服务'
W '[2] 检查远程桌面服务（TermService）'
sc.exe query TermService 2>&1 | ForEach-Object { W $_ }
sc.exe qc TermService 2>&1 | ForEach-Object { W $_ }
try {
    $service=Get-Service TermService -ErrorAction Stop; $start=(Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService' -Name Start -ErrorAction Stop).Start
    $actual="状态={0}，启动类型={1}" -f $(if($service.Status -eq 'Stopped'){'已停止'}else{[string]$service.Status}),$(if($start -eq 4){'已禁用'}else{"Start=$start"})
    W ("结果：{0}" -f $actual); S '远程桌面服务' '已停止、已禁用' $actual $(if($service.Status -eq 'Stopped' -and $start -eq 4){'通过'}else{'异常'})
} catch { W '结果：无法读取远程桌面服务。'; S '远程桌面服务' '已停止、已禁用' '无法读取' '异常' }
W ''
ShowStep '远程桌面连接策略'
W '[3] 检查远程桌面注册表配置'
reg.exe query 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections 2>&1 | ForEach-Object { W $_ }
try {$rdp=(Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections;S '远程桌面连接策略' '禁止连接（值为1）' $(if($rdp -eq 1){'已禁止连接（值为1）'}else{"当前值=$rdp"}) $(if($rdp -eq 1){'通过'}else{'异常'})}catch{S '远程桌面连接策略' '禁止连接（值为1）' '无法读取' '异常'}
W '预期：fDenyTSConnections 为 0x1。'; W ''
ShowStep '防火墙阻断规则'
W '[4] 检查防火墙规则'
$ruleNames=@('TCP-22','TCP-135','UDP-137','UDP-138','TCP-139','TCP-445','TCP-3389','UDP-3389')
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
ShowStep 'NetBIOS 网卡配置'
W '[5] 检查 NetBIOS 配置'
reg.exe query 'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' /s /v NetbiosOptions 2>&1 | ForEach-Object { W $_ }
try{$interfaces=Get-ChildItem -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction Stop;$netbiosTotal=0;$netbiosPassed=0;foreach($interface in $interfaces){$netbiosTotal++;$option=(Get-ItemProperty -LiteralPath $interface.PSPath -Name NetbiosOptions -ErrorAction Stop).NetbiosOptions;$conclusion=$(if($option -eq 2){$netbiosPassed++;'通过'}else{'异常'});$netbiosRows+=New-Object PSObject -Property @{Interface=$interface.PSChildName;Expected=2;Actual=$option;Conclusion=$conclusion}};S 'NetBIOS 配置汇总' '所有网卡均禁用（值为2）' ("{0}/{1}个网卡为禁用" -f $netbiosPassed,$netbiosTotal) $(if($netbiosTotal -gt 0 -and $netbiosPassed -eq $netbiosTotal){'通过'}else{'异常'})}catch{S 'NetBIOS 配置汇总' '所有网卡均禁用（值为2）' '无法完整读取' '异常'}
W '预期：各网卡 NetbiosOptions 为 0x2。'; W ''
ShowStep '本机端口监听'
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

ShowStep '网络配置注册表记录'
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

ShowStep 'USB 存储设备注册表记录'
W '[8] USB 存储设备注册表记录（USBSTOR）'
W "序号`t设备类型`t实例 ID/序列号`t友好名称`t设备描述`t厂商"
$usbReadError=''
try {
    $usbRoot='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR'
    $rootMissing=$false
    try{$null=Get-Item -LiteralPath $usbRoot -ErrorAction Stop}catch [System.Management.Automation.ItemNotFoundException]{$rootMissing=$true}
    $devices=@();if(!$rootMissing){$devices=@(Get-ChildItem -LiteralPath $usbRoot -ErrorAction Stop)}
    $index=0
    foreach($device in $devices) {
        foreach($instance in (Get-ChildItem -LiteralPath $device.PSPath -ErrorAction Stop)) {
            $index++; $item=Get-ItemProperty -LiteralPath $instance.PSPath -ErrorAction Stop
            W ("{0}`t{1}`t{2}`t{3}`t{4}`t{5}" -f $index,(V $device.PSChildName),(V $instance.PSChildName),(V $item.FriendlyName),(V $item.DeviceDesc),(V $item.Mfg))
            $usbRows+=New-Object PSObject -Property @{Index=$index;Type=(V $device.PSChildName);Instance=(V $instance.PSChildName);Name=(V $item.FriendlyName);Description=(V $item.DeviceDesc);Manufacturer=(V $item.Mfg)}
        }
    }
    if($index -eq 0){W "-`t未发现 USB 存储设备记录"};S 'USB 存储设备记录' '清理后应为0条；历史记录需现场核查' $(if($index -eq 0){'未发现 USB 存储设备记录（0条）'}else{"读取成功，剩余$index 条"}) $(if($index -eq 0){'通过'}else{'需复核'})
} catch { $usbReadError=$_.Exception.Message;W ("错误`t无法读取 USBSTOR：{0}" -f $usbReadError);S 'USB 存储设备记录' '清理后应为0条；历史记录需现场核查' '读取失败' '异常' }
W ''

function AddBrowserRow([string]$browser,[string]$check,[string]$scope,[string]$source,[string]$expected,[string]$actual,[string]$conclusion,[string]$evidence){
    $script:browserRows+=New-Object PSObject -Property @{Browser=$browser;Check=$check;Scope=$scope;Source=$source;Expected=$expected;Actual=$actual;Conclusion=$conclusion;Evidence=$evidence}
}
function TestBrowserInstalled([string]$executable,[string[]]$paths){
    foreach($path in $paths){if($path -and (Test-Path -LiteralPath $path)){return $true}}
    foreach($base in @('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths','Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths','Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths')){
        if(Test-Path -LiteralPath (Join-Path $base $executable)){return $true}
    }
    return $false
}
function AddBrowserInstallation([string]$browser,[bool]$installed){
    if($installed){AddBrowserRow $browser '安装状态' '本机' '程序文件/App Paths' '仅记录' '已安装' '已识别' '检测到浏览器程序或安装注册信息'}
    else{AddBrowserRow $browser '安装状态' '本机' '程序文件/App Paths' '仅记录' '未安装' '不适用' '未检测到浏览器程序或安装注册信息'}
}
$script:accountRows=@()
function AddAccountRow([string]$browser,[string]$profile,[string]$website,[string]$account){
    $script:accountRows+=New-Object PSObject -Property @{Browser=$browser;Profile=$profile;Website=$website;Account=$account}
}
function AddChromiumSavedPasswords([string]$browser,[string]$root,[string]$counter){
    $files=@();if($root -and (Test-Path -LiteralPath $root)){$files=@(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue|Where-Object {$_.PSIsContainer -and $true}|ForEach-Object {Join-Path $_.FullName 'Login Data';Join-Path $_.FullName 'Login Data For Account'}|Where-Object {Test-Path -LiteralPath $_})}
    if($files.Count -eq 0){AddBrowserRow $browser '已保存密码' '当前用户' '密码库' '没有保存密码' '未发现保存密码（0条）' '通过' '未发现当前用户密码库';return}
    foreach($file in $files){
        $profile=(Split-Path (Split-Path $file -Parent) -Leaf)+' / '+(Split-Path $file -Leaf)
        if(!$counter -or !(Test-Path -LiteralPath $counter)){AddBrowserRow $browser '已保存密码' $profile '密码库' '没有保存密码' '无法执行计数' '需复核' '同目录缺少可用的现场检查程序';continue}
        $previousEncoding=[Console]::OutputEncoding
        try{[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);$output=@(& $counter /list-chromium-logins $file 2>$null);$code=$LASTEXITCODE;$decoded=ConvertFrom-Json -InputObject ($output -join '') -ErrorAction Stop;$records=@($decoded | Where-Object {$null -ne $_});$count=$records.Count;$parsed=$true
            if($code -eq 0){foreach($record in $records){$website=[string]$record.website;$account=[string]$record.account;if(!$website){$website='未记录网站地址'};if(!$account){$account='未记录账号'};AddAccountRow $browser $profile $website $account}}
        }catch{$code=6;$parsed=$false;$count=0}finally{[Console]::OutputEncoding=$previousEncoding}
        if($code -ne 0 -or !$parsed){AddBrowserRow $browser '已保存密码' $profile '密码库' '没有保存密码' '读取失败' '需复核' '密码库可能正被占用或格式不受支持'}
        elseif($count -eq 0){AddBrowserRow $browser '已保存密码' $profile '密码库' '没有保存密码' '未发现保存密码（0条）' '通过' '只统计记录数量，不读取或解密字段内容'}
        else{AddBrowserRow $browser '已保存密码' $profile '密码库' '没有保存密码' ("发现保存密码（{0}条）" -f $count) '异常' '网站和账号见下方明细；不读取或解密密码内容'}
    }
}
function AddFirefoxSavedPasswords([string]$root){
    $files=@();if($root -and (Test-Path -LiteralPath $root)){$files=@(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue|Where-Object {$_.PSIsContainer}|ForEach-Object {Join-Path $_.FullName 'logins.json'}|Where-Object {Test-Path -LiteralPath $_})}
    if($files.Count -eq 0){AddBrowserRow 'Mozilla Firefox' '已保存密码' '当前用户' '密码库' '没有保存密码' '未发现保存密码（0条）' '通过' '未发现当前用户密码库';return}
    foreach($file in $files){$profile=Split-Path (Split-Path $file -Parent) -Leaf;try{$text=[IO.File]::ReadAllText($file);if($text -notmatch '"logins"\s*:\s*\['){throw '密码库格式无法识别'};$entries=@(($text|ConvertFrom-Json -ErrorAction Stop).logins);$count=$entries.Count;foreach($entry in $entries){AddAccountRow 'Mozilla Firefox' $profile ([string]$entry.hostname) '账号已加密，请在 Firefox 密码管理中查看'};if($count -eq 0){AddBrowserRow 'Mozilla Firefox' '已保存密码' $profile '密码库' '没有保存密码' '未发现保存密码（0条）' '通过' '只统计记录数量，不读取或解密字段内容'}else{AddBrowserRow 'Mozilla Firefox' '已保存密码' $profile '密码库' '没有保存密码' ("发现保存密码（{0}条）" -f $count) '异常' '只统计记录数量，不读取或解密字段内容'}}catch{AddBrowserRow 'Mozilla Firefox' '已保存密码' $profile '密码库' '没有保存密码' '读取失败' '需复核' $_.Exception.Message}}
}
function AddInternetExplorerSavedPasswords {
    try{
        $registryCount=0;$key='Registry::HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\IntelliForms\Storage2';if(Test-Path -LiteralPath $key){$registryCount=@((Get-Item -LiteralPath $key -ErrorAction Stop).GetValueNames()|Where-Object {$_}).Count}
        $winInetCount=0;$cmdkey=Join-Path $env:SystemRoot 'System32\cmdkey.exe';if(Test-Path -LiteralPath $cmdkey){$listing=(& $cmdkey /list 2>$null) -join "`n";$winInetCount=[regex]::Matches($listing,'Microsoft_WinInet_','IgnoreCase').Count}
        if($registryCount -gt 0 -or $winInetCount -gt 0){AddAccountRow 'Internet Explorer' '当前用户' '旧版索引无法还原网站' '请在浏览器密码管理中查看';AddBrowserRow 'Internet Explorer' '已保存密码' '当前用户' 'IE/WinInet 密码存储' '没有保存密码' '发现保存密码记录' '异常' '仅检查密码记录索引，不读取或解密内容'}
        else{AddBrowserRow 'Internet Explorer' '已保存密码' '当前用户' 'IE/WinInet 密码存储' '没有保存密码' '未发现保存密码（0条）' '通过' '未发现 IE 或 WinInet 密码记录索引'}
    }catch{AddBrowserRow 'Internet Explorer' '已保存密码' '当前用户' 'IE/WinInet 密码存储' '没有保存密码' '读取失败' '需复核' $_.Exception.Message}
}

if($Interactive){
    ShowStep '浏览器已保存密码检查（只统计条目）'
    W '[9] 浏览器已保存密码检查'
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$isSystem=$identity.IsSystem
    if($isSystem){AddBrowserRow '运行身份' '检查身份' 'SYSTEM' '运行身份' '检查当前登录用户' 'SYSTEM 无法代表当前登录用户' '需复核' '系统加固项仍会正常检查；浏览器密码请由用户本人运行现场检查版复核'}
    if(!$InspectorPath){$preferred=$(if([Environment]::Is64BitOperatingSystem){'安全检查-64位.exe'}else{'安全检查-32位.exe'});$candidate=Join-Path $base $preferred;if(Test-Path -LiteralPath $candidate){$InspectorPath=$candidate}else{$candidate=Join-Path $base '安全检查-32位.exe';if(Test-Path -LiteralPath $candidate){$InspectorPath=$candidate}}}

    $edgePaths=@($(if($env:ProgramFiles){Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe'}),$(if(${env:ProgramFiles(x86)}){Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'}),$(if($env:LOCALAPPDATA){Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\Application\msedge.exe'}));$edgeInstalled=TestBrowserInstalled 'msedge.exe' $edgePaths;AddBrowserInstallation 'Microsoft Edge' $edgeInstalled
    if($edgeInstalled){if($isSystem){AddBrowserRow 'Microsoft Edge' '已保存密码' '登录用户' '运行身份' '没有保存密码' 'SYSTEM 无法检查登录用户' '需复核' '请由用户本人运行现场检查版'}else{$edgeRoot=$(if($env:LOCALAPPDATA){Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data'}else{''});AddChromiumSavedPasswords 'Microsoft Edge' $edgeRoot $InspectorPath}}

    $chromePaths=@($(if($env:ProgramFiles){Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'}),$(if(${env:ProgramFiles(x86)}){Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe'}),$(if($env:LOCALAPPDATA){Join-Path $env:LOCALAPPDATA 'Google\Chrome\Application\chrome.exe'}));$chromeInstalled=TestBrowserInstalled 'chrome.exe' $chromePaths;AddBrowserInstallation 'Google Chrome' $chromeInstalled
    if($chromeInstalled){if($isSystem){AddBrowserRow 'Google Chrome' '已保存密码' '登录用户' '运行身份' '没有保存密码' 'SYSTEM 无法检查登录用户' '需复核' '请由用户本人运行现场检查版'}else{$chromeRoot=$(if($env:LOCALAPPDATA){Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data'}else{''});AddChromiumSavedPasswords 'Google Chrome' $chromeRoot $InspectorPath}}

    $firefoxPaths=@($(if($env:ProgramFiles){Join-Path $env:ProgramFiles 'Mozilla Firefox\firefox.exe'}),$(if(${env:ProgramFiles(x86)}){Join-Path ${env:ProgramFiles(x86)} 'Mozilla Firefox\firefox.exe'}),$(if($env:LOCALAPPDATA){Join-Path $env:LOCALAPPDATA 'Mozilla Firefox\firefox.exe'}));$firefoxInstalled=TestBrowserInstalled 'firefox.exe' $firefoxPaths;AddBrowserInstallation 'Mozilla Firefox' $firefoxInstalled
    if($firefoxInstalled){if($isSystem){AddBrowserRow 'Mozilla Firefox' '已保存密码' '登录用户' '运行身份' '没有保存密码' 'SYSTEM 无法检查登录用户' '需复核' '请由用户本人运行现场检查版'}else{$firefoxRoot=$(if($env:APPDATA){Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles'}else{''});AddFirefoxSavedPasswords $firefoxRoot}}

    $iePaths=@($(if($env:ProgramFiles){Join-Path $env:ProgramFiles 'Internet Explorer\iexplore.exe'}),$(if(${env:ProgramFiles(x86)}){Join-Path ${env:ProgramFiles(x86)} 'Internet Explorer\iexplore.exe'}));$ieInstalled=TestBrowserInstalled 'iexplore.exe' $iePaths;AddBrowserInstallation 'Internet Explorer' $ieInstalled
    if($ieInstalled){if($isSystem){AddBrowserRow 'Internet Explorer' '已保存密码' '登录用户' '运行身份' '没有保存密码' 'SYSTEM 无法检查登录用户' '需复核' '请由用户本人运行现场检查版'}else{AddInternetExplorerSavedPasswords}}

    $settingRows=@($browserRows|Where-Object {$_.Check -eq '已保存密码' -or $_.Check -eq '检查身份'});$browserFailed=@($settingRows|Where-Object {$_.Conclusion -eq '异常'}).Count;$browserReview=@($settingRows|Where-Object {$_.Conclusion -eq '需复核'}).Count;$browserPassed=@($settingRows|Where-Object {$_.Conclusion -eq '通过'}).Count
    $browserInstalledCount=@($browserRows|Where-Object {$_.Check -eq '安装状态' -and $_.Actual -eq '已安装'}).Count;$browserNotInstalledCount=@($browserRows|Where-Object {$_.Check -eq '安装状态' -and $_.Actual -eq '未安装'}).Count
    $browserConclusion=$(if($browserFailed -gt 0){'异常'}elseif($browserReview -gt 0){'需复核'}else{'通过'})
    S '浏览器已保存密码' '已安装浏览器均没有保存密码' ("已安装{0}个，未安装{1}个；无密码{2}项，有密码{3}项，需复核{4}项" -f $browserInstalledCount,$browserNotInstalledCount,$browserPassed,$browserFailed,$browserReview) $browserConclusion
    W ("浏览器安装：已安装{0}个，未安装{1}个；保存密码检查：通过{2}项，异常{3}项，需复核{4}项" -f $browserInstalledCount,$browserNotInstalledCount,$browserPassed,$browserFailed,$browserReview);W ''
}

$wirelessRows=@()
try{
    . (Join-Path $base 'wireless-remediator.ps1')
    $wirelessRows=@(Get-WirelessInspection)
    foreach($entry in $wirelessRows){S $entry.Item $entry.Expected $entry.Actual $entry.Conclusion}
}catch{S '无线网络检查' '无已保存 Wi-Fi 配置且无线网卡禁用' ('检查失败：'+$_.Exception.Message) '需复核'}
$passed=@($summary|Where-Object {$_.Conclusion -eq '通过'}).Count;$failed=@($summary|Where-Object {$_.Conclusion -eq '异常'}).Count;$review=@($summary|Where-Object {$_.Conclusion -eq '需复核'}).Count
$finished=Get-Date
W ("验证结束：{0}" -f $finished)
if($failed -eq 0){$overallClass='pass';$overallText='本机配置检查未发现异常；端口是否真正无法从外部访问，仍需从另一台电脑测试。'}else{$overallClass='fail';$overallText='存在未达到预期的项目，请先处理“异常”项，再重新验证。'}

$html=New-Object System.Text.StringBuilder
[void]$html.AppendLine('<!doctype html>')
[void]$html.AppendLine('<html lang="zh-CN"><head><meta charset="utf-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><title>高危端口阻断验证报告</title>')
    [void]$html.AppendLine('<style>body{margin:0;background:#f3f5f7;color:#202124;font-family:"Microsoft YaHei",Arial,sans-serif;font-size:14px;line-height:1.6}.wrap{max-width:1200px;margin:24px auto;padding:0 18px}.header,.card{background:#fff;border:1px solid #dfe3e8;border-radius:6px;margin-bottom:18px;padding:20px}.header h1{margin:0 0 8px;font-size:24px}.meta{color:#687078}.banner{border-left:6px solid #2e7d32}.banner.fail{border-left-color:#c62828}.counts{font-size:18px;margin:8px 0}.pass{color:#1b5e20;font-weight:bold}.fail{color:#b71c1c;font-weight:bold}.review{color:#9a6700;font-weight:bold}.info{color:#1565c0;font-weight:bold}.na{color:#687078;font-weight:bold}h2{font-size:19px;margin:0 0 12px;padding-bottom:8px;border-bottom:2px solid #e7eaed}table{width:100%;border-collapse:collapse;table-layout:auto}th,td{border:1px solid #d9dde2;padding:8px 10px;text-align:left;vertical-align:top;word-break:break-all}th{background:#eef2f5;white-space:nowrap}.scroll{overflow-x:auto}.note{background:#fff8e1;border:1px solid #f0d98a;padding:10px 12px;margin-top:12px}pre{white-space:pre-wrap;word-wrap:break-word;background:#f7f8fa;border:1px solid #dfe3e8;padding:14px;max-height:520px;overflow:auto}.small{font-size:12px;color:#687078}</style></head><body><div class="wrap">')
[void]$html.AppendLine(('<div class="header banner {0}"><h1>高危端口阻断验证报告</h1><div class="meta">被检查终端IP地址:{1}  MAC地址：{2}</div><div class="meta">主用网卡：{3}　计算机：{4}　验证时间：{5}</div><div class="counts">通过 <span class="pass">{6}</span> 项　异常 <span class="fail">{7}</span> 项　需人工复核 <span class="review">{8}</span> 项</div><div>{9}</div></div>' -f $overallClass,(EncodeHtml $terminalNetwork.IP),(EncodeHtml $terminalNetwork.MAC),(EncodeHtml $terminalNetwork.Interface),(EncodeHtml $env:COMPUTERNAME),(EncodeHtml $finished.ToString('yyyy-MM-dd HH:mm:ss')),$passed,$failed,$review,(EncodeHtml $overallText)))

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
if($usbReadError){[void]$html.AppendLine(('<tr><td colspan="6" class="fail">USB 记录读取失败，无法确定是否为空：{0}</td></tr>' -f (EncodeHtml $usbReadError)))}
elseif($usbRows.Count -eq 0){[void]$html.AppendLine('<tr><td colspan="6">未发现 USB 存储设备记录（0条）</td></tr>')}
[void]$html.AppendLine('</tbody></table></div></div>')

if($Interactive){
    [void]$html.AppendLine('<div class="card"><h2>六、浏览器已保存密码逐项明细</h2><p class="note">隐私说明：本功能只判断是否存在已保存密码并统计条目数量，列出网站地址和保存账号，不解密、不显示、不导出密码及 Cookie。没有保存密码为“通过”；存在保存密码为“异常”；未安装浏览器为“不适用”。</p><div class="scroll"><table><thead><tr><th>序号</th><th>浏览器</th><th>检查项目</th><th>范围/配置文件</th><th>来源</th><th>预期结果</th><th>实际结果</th><th>结论</th><th>判断依据</th></tr></thead><tbody>')
    $i=0;foreach($row in $browserRows){$i++;[void]$html.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td class="{7}">{8}</td><td>{9}</td></tr>' -f $i,(EncodeHtml $row.Browser),(EncodeHtml $row.Check),(EncodeHtml $row.Scope),(EncodeHtml $row.Source),(EncodeHtml $row.Expected),(EncodeHtml $row.Actual),(C $row.Conclusion),(EncodeHtml $row.Conclusion),(EncodeHtml $row.Evidence)))}
    [void]$html.AppendLine('</tbody></table></div></div>')
}

if($Interactive){
    [void]$html.AppendLine('<div class="card"><h2>保存密码的网站与账号</h2><p class="note">本表包含账号信息，请按内部检查资料保管。Firefox 加密账号和 IE 旧索引无法直接读取时会明确说明。</p><div class="scroll"><table><thead><tr><th>序号</th><th>浏览器</th><th>用户配置</th><th>网站地址</th><th>保存的账号</th></tr></thead><tbody>')
    $i=0;foreach($row in $accountRows){$i++;[void]$html.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f $i,(EncodeHtml $row.Browser),(EncodeHtml $row.Profile),(EncodeHtml $row.Website),(EncodeHtml $row.Account)))}
    if($accountRows.Count -eq 0){[void]$html.AppendLine('<tr><td colspan="5">没有可列出的网站与账号；是否通过请以浏览器检查结论为准，读取失败或 SYSTEM 身份仍需复核。</td></tr>')}
    [void]$html.AppendLine('</tbody></table></div></div>')
}
[void]$html.AppendLine(('<div class="card"><h2>{0}、原始检查信息</h2><p class="small">用于管理员进一步排查，普通使用者优先查看前面的汇总和逐项明细。</p><pre>{1}</pre></div>' -f $(if($Interactive){'七'}else{'六'}),(EncodeHtml ($details -join "`r`n"))))
[void]$html.AppendLine('<div class="card"><h2>无线网络配置与网卡复检</h2><p class="note">Wi-Fi 配置与 NetworkList 历史分开检查。历史按 NameType 分类：71 为无线，6 为有线，其余或缺失为未知；不按名称猜测。清理版仅删除明确无线历史，有线保留，未知需人工确认。未连接不等于禁用。</p>')
if(Get-Command Get-NetworkHistoryManualHelp -ErrorAction SilentlyContinue){[void]$html.AppendLine(('<p class="note">{0}</p>' -f (EncodeHtml (Get-NetworkHistoryManualHelp))))}
[void]$html.AppendLine('<table><tr><th>检查项目</th><th>预期</th><th>实际</th><th>结论</th></tr>')
foreach($entry in $wirelessRows){[void]$html.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td class="{3}">{4}</td></tr>' -f (EncodeHtml $entry.Item),(EncodeHtml $entry.Expected),(EncodeHtml $entry.Actual),(C $entry.Conclusion),(EncodeHtml $entry.Conclusion)))}
if($wirelessRows.Count -eq 0){[void]$html.AppendLine('<tr><td colspan="4">无线检查未完成，请查看汇总失败原因。</td></tr>')}
[void]$html.AppendLine('</table></div>')
[void]$html.AppendLine('</div></body></html>')
$utf8=New-Object System.Text.UTF8Encoding($true)
[System.IO.File]::WriteAllText($report,$html.ToString(),$utf8)
if(Test-Path -LiteralPath $legacyLog){Remove-Item -LiteralPath $legacyLog -Force}
Write-Host "验证完成，HTML 报告：$report"
if($Interactive){Write-Host ("现场检查汇总：通过 {0} 项，异常 {1} 项，需复核 {2} 项。" -f $passed,$failed,$review) -ForegroundColor Yellow}
if($ExitWithStatus){if($failed -gt 0){exit 5}else{exit 0}}
