param([string]$ModulePath)
$ErrorActionPreference='Stop'
. $ModulePath
if((Get-NetworkHistoryKind 71) -ne '无线'){throw 'Wireless classification'}
if((Get-NetworkHistoryKind 6) -ne '有线'){throw 'Wired classification'}
foreach($value in @($null,0,23,243,999)){if((Get-NetworkHistoryKind $value) -ne '未知'){throw 'Unsafe classification'}}
function Get-WirelessAdapters {return}
function Get-WirelessProfileFiles {return}
function Get-NetworkHistory {
 [pscustomobject]@{Name='Ethernet';Guid='{00000000-0000-0000-0000-000000000071}';NameType=71;Kind=(Get-NetworkHistoryKind 71)}
 [pscustomobject]@{Name='Xiaomi hotspot';Guid='{00000000-0000-0000-0000-000000000006}';NameType=6;Kind=(Get-NetworkHistoryKind 6)}
 [pscustomobject]@{Name='Wi-Fi';Guid='{00000000-0000-0000-0000-000000000000}';NameType=$null;Kind=(Get-NetworkHistoryKind $null)}
}
$script:deleted=@()
function Remove-NetworkHistory($guid){$script:deleted+=$guid}
$rows=@(Invoke-WirelessCleanup)
if($deleted.Count -ne 1 -or $deleted[0] -notlike '*0071}'){throw 'Selection deleted non-wireless history'}
if(@($rows|Where-Object {$_.Status -eq '需人工处理' -and $_.Note -match 'regedit'}).Count -ne 1){throw 'Missing manual instructions'}
$inspection=@(Get-WirelessInspection)
if(@($inspection|Where-Object {$_.Item -like '网络历史*' -and $_.Conclusion -eq '异常'}).Count -ne 1){throw 'Wireless inspection'}
function Remove-NetworkHistory($guid){throw 'Access denied fixture'}
$rows=@(Invoke-WirelessCleanup)
if(@($rows|Where-Object {$_.Status -eq '失败/需复核'}).Count -ne 1){throw 'Failure misreported'}
Write-Host 'PASS: exact type selection, wired and unknown preservation, manual help, inspection and failure'
