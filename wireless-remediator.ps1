# Shared read-only inventory and explicitly requested wireless cleanup.
function Get-WirelessAdapters {
    if(!(Get-Command Get-NetAdapter -ErrorAction SilentlyContinue)){throw '系统缺少 Get-NetAdapter，无法可靠识别无线硬件；请人工处理（此无线功能需要 Windows 8/Server 2012 或更新系统）'}
    @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {[int]$_.NdisPhysicalMedium -in @(1,9) -or [int]$_.NdisMedium -eq 16})
}
function Get-WirelessProfileFiles {
    $path=Join-Path $env:ProgramData 'Microsoft\Wlansvc\Profiles\Interfaces'
    try{$root=Get-Item -LiteralPath $path -ErrorAction Stop}catch [System.Management.Automation.ItemNotFoundException]{return}
    if(!$root.PSIsContainer){throw '无线配置存储位置不是目录'}
    # Count filenames only. Do not read XML contents or saved wireless keys.
    @(Get-ChildItem -LiteralPath $path -Filter '*.xml' -Recurse -File -ErrorAction Stop)
}
function Get-WirelessInspection {
    $result=New-Object System.Collections.ArrayList
    try{$profiles=@(Get-WirelessProfileFiles);[void]$result.Add([pscustomobject]@{Item='已保存 Wi-Fi 配置';Expected='本机 WLAN 配置文件为0';Actual=("剩余 {0} 个配置文件" -f $profiles.Count);Conclusion=$(if($profiles.Count -eq 0){'通过'}else{'异常'})})}
    catch{[void]$result.Add([pscustomobject]@{Item='已保存 Wi-Fi 配置';Expected='本机 WLAN 配置文件为0';Actual=('读取失败：'+$_.Exception.Message);Conclusion='需复核'})}
    try{
        $adapters=@(Get-WirelessAdapters)
        if($adapters.Count -eq 0){[void]$result.Add([pscustomobject]@{Item='无线网卡';Expected='全部禁用';Actual='未识别到无线网卡';Conclusion='不适用'})}
        foreach($adapter in $adapters){$disabled=[int]$adapter.InterfaceAdminStatus -eq 2;[void]$result.Add([pscustomobject]@{Item=('无线网卡 / '+$adapter.Name);Expected='管理状态为禁用';Actual=$(if($disabled){'已禁用'}else{'未禁用（未连接不等于已禁用）'});Conclusion=$(if($disabled){'通过'}else{'异常'})})}
    }catch{[void]$result.Add([pscustomobject]@{Item='无线网卡';Expected='全部禁用';Actual=('无法识别：'+$_.Exception.Message);Conclusion='需复核'})}
    try{foreach($entry in @(Get-NetworkHistory)){
        [void]$result.Add([pscustomobject]@{Item=('网络历史 / '+$entry.Name+' / '+$entry.Guid);Expected='无线历史清空；有线保留；未知人工确认';Actual=($entry.Kind+'；NameType='+$entry.NameType);Conclusion=$(if($entry.Kind -eq '无线'){'异常'}elseif($entry.Kind -eq '有线'){'不适用'}else{'需复核'})})
    }}catch{[void]$result.Add([pscustomobject]@{Item='网络历史';Expected='可读取并分类';Actual=$_.Exception.Message;Conclusion='需复核'})}
    return $result.ToArray()
}
function Remove-WirelessProfiles {
    $service=Get-Service -Name WlanSvc -ErrorAction Stop
    if($service.Status -ne 'Running'){Start-Service -Name WlanSvc -ErrorAction Stop}
    $netsh=Join-Path $env:SystemRoot 'System32\netsh.exe'
    $output=@(& $netsh wlan delete profile 'name=*' 2>&1)
    return $LASTEXITCODE
}
function Invoke-WirelessCleanup {
    $result=New-Object System.Collections.ArrayList
    # Resolve precise adapter objects before any mutation; never disable an adapter by name matching.
    try{$adapters=@(Get-WirelessAdapters)}catch{[void]$result.Add([pscustomobject]@{Item='无线清理';Before='?';Removed=0;After='?';Status='失败/需复核';Note=$_.Exception.Message});return $result.ToArray()}
    $before='?';$after='?'
    try{
        $profiles=@(Get-WirelessProfileFiles);$before=$profiles.Count
        if($before -gt 0){
            $code=Remove-WirelessProfiles
            $after=@(Get-WirelessProfileFiles).Count
            if($code -ne 0 -or $after -ne 0){throw ("无线配置未全部删除：命令返回 {0}，剩余 {1} 个；策略配置、已禁用或已移除网卡配置可能需要人工处理" -f $code,$after)}
        }else{$after=0}
        [void]$result.Add([pscustomobject]@{Item='已保存 Wi-Fi 配置';Before=$before;Removed=($before-$after);After=$after;Status=$(if($before -eq 0){'原本无记录'}else{'已清空'});Note='使用 Windows WLAN 命令删除配置；仅统计文件，不读取无线密码'})
    }catch{[void]$result.Add([pscustomobject]@{Item='已保存 Wi-Fi 配置';Before=$before;Removed=$(if($before -is [int] -and $after -is [int]){[Math]::Max(0,$before-$after)}else{'?'});After=$after;Status='失败/需复核';Note=$_.Exception.Message})}
    foreach($adapter in $adapters){
        $beforeDisabled=[int]$adapter.InterfaceAdminStatus -eq 2
        try{
            if(!$beforeDisabled){$adapter|Disable-NetAdapter -Confirm:$false -ErrorAction Stop}
            $current=@(Get-WirelessAdapters|Where-Object {$_.InterfaceGuid -eq $adapter.InterfaceGuid})
            if($current.Count -ne 1 -or [int]$current[0].InterfaceAdminStatus -ne 2){throw '无法确认无线网卡管理状态已禁用'}
            [void]$result.Add([pscustomobject]@{Item=('无线网卡 / '+$adapter.Name);Before=$(if($beforeDisabled){'已禁用'}else{'未禁用'});Removed='-';After='已禁用';Status=$(if($beforeDisabled){'原本已禁用'}else{'已禁用'});Note='只修改已识别无线网卡的管理状态，不修改有线 IP、网关或 DNS'})
        }catch{[void]$result.Add([pscustomobject]@{Item=('无线网卡 / '+$adapter.Name);Before=$(if($beforeDisabled){'已禁用'}else{'未禁用'});Removed='-';After='?';Status='失败/需复核';Note=$_.Exception.Message})}
    }
    if($adapters.Count -eq 0){[void]$result.Add([pscustomobject]@{Item='无线网卡';Before=0;Removed=0;After=0;Status='未发现';Note='未识别到无线硬件'})}
    try{foreach($entry in @(Get-NetworkHistory)){
        $status='保留';$after=1;$removed=0
        $note=('类型：'+$entry.Kind+'；NameType='+$entry.NameType+'；GUID='+$entry.Guid)
        if($entry.Kind -eq '无线'){
            try{Remove-NetworkHistory $entry.Guid;$after=0;$removed=1;$status='已清空'}catch{$status='失败/需复核';$after='?';$note+='；'+$_.Exception.Message}
        }elseif($entry.Kind -eq '未知'){$status='需人工处理';$note+='；'+(Get-NetworkHistoryManualHelp)}
        [void]$result.Add([pscustomobject]@{Item=('网络历史 / '+$entry.Name);Before=1;Removed=$removed;After=$after;Status=$status;Note=$note})
    }}catch{[void]$result.Add([pscustomobject]@{Item='网络历史';Before='?';Removed=0;After='?';Status='失败/需复核';Note=$_.Exception.Message})}
    return $result.ToArray()
}

function Get-NetworkHistoryManualHelp {
    '人工方法：先保存报告，确认该 GUID 对应无线且不是当前有线网络；管理员运行 regedit，在 HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles 中找到该 GUID，先导出备份，再删除该单个子项；Signatures\Unmanaged 下仅处理 ProfileGuid 与其完全相同的子项（先导出）。无法确认、Managed 策略项或拒绝访问时停止，交管理员核查；不要删除整个 Profiles/Signatures，也不要修改权限。Wi-Fi 配置另在设置→网络和 Internet→Wi-Fi→管理已知网络中选择对应网络→忘记。最后重新检查。'
}
function Get-NetworkHistoryKind($nameType) {
    # NameType follows interface type identifiers; missing/unrecognized values are never guessed from names.
    if($null -ne $nameType -and [int]$nameType -eq 71){return '无线'}
    if($null -ne $nameType -and [int]$nameType -eq 6){return '有线'}
    return '未知'
}
function Open-NetworkHistoryRoot([bool]$writable=$false) {
    $view=if([Environment]::Is64BitOperatingSystem){[Microsoft.Win32.RegistryView]::Registry64}else{[Microsoft.Win32.RegistryView]::Registry32}
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$view)
    try{return $base.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList',$writable)}finally{$base.Dispose()}
}
function Get-NetworkHistory {
    $root=Open-NetworkHistoryRoot
    if($null -eq $root){return}
    try{
        $profiles=$root.OpenSubKey('Profiles')
        if($null -eq $profiles){return}
        try{foreach($guid in $profiles.GetSubKeyNames()){
            $key=$profiles.OpenSubKey($guid)
            if($null -eq $key){throw ('记录在读取期间消失：'+$guid)}
            try{$type=$key.GetValue('NameType',$null);[pscustomobject]@{Guid=$guid;Name=[string]$key.GetValue('ProfileName','');NameType=$type;Kind=(Get-NetworkHistoryKind $type)}}finally{$key.Dispose()}
        }}finally{$profiles.Dispose()}
    }finally{$root.Dispose()}
}
function Remove-NetworkHistory([string]$guid) {
    $parsed=[guid]::Empty
    if(![guid]::TryParse($guid,[ref]$parsed)){throw '无效的配置 GUID'}
    $root=Open-NetworkHistoryRoot $true
    if($null -eq $root){return}
    try{
        $profile=$root.OpenSubKey('Profiles\'+$guid)
        if($null -eq $profile){return}
        try{if((Get-NetworkHistoryKind $profile.GetValue('NameType',$null)) -ne '无线'){throw '复检类型已变化，拒绝删除'}}finally{$profile.Dispose()}
        $matches=@()
        foreach($scope in @('Managed','Unmanaged')){
            $signatures=$root.OpenSubKey('Signatures\'+$scope)
            if($null -eq $signatures){continue}
            try{foreach($name in $signatures.GetSubKeyNames()){
                $key=$signatures.OpenSubKey($name)
                if($null -eq $key){throw '签名在读取期间消失'}
                try{if([string]$key.GetValue('ProfileGuid','') -ieq $guid){
                    if($scope -eq 'Managed'){throw '存在 Managed 策略关联记录，保留并交管理员处理'}
                    $matches+=('Signatures\Unmanaged\'+$name)
                }}finally{$key.Dispose()}
            }}finally{$signatures.Dispose()}
        }
        foreach($path in $matches){$root.DeleteSubKeyTree($path,$false)}
        $root.DeleteSubKeyTree(('Profiles\'+$guid),$false)
        $remaining=$root.OpenSubKey('Profiles\'+$guid)
        if($null -ne $remaining){$remaining.Dispose();throw '删除后仍存在记录'}
    }finally{$root.Dispose()}
}
