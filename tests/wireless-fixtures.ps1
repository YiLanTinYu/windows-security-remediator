param([string]$ModulePath)
$ErrorActionPreference='Stop'
. $ModulePath
function Get-NetworkHistory {return}
$script:adapters=@(
 [pscustomobject]@{Name='Ethernet named Wi-Fi';NdisPhysicalMedium=14;NdisMedium=0;InterfaceAdminStatus=1;InterfaceGuid='wired'},
 [pscustomobject]@{Name='Wireless renamed Ethernet';NdisPhysicalMedium=9;NdisMedium=16;InterfaceAdminStatus=1;InterfaceGuid='wifi'},
 [pscustomobject]@{Name='Bluetooth';NdisPhysicalMedium=10;NdisMedium=0;InterfaceAdminStatus=1;InterfaceGuid='bluetooth'}
)
$script:files=@('one.xml','two.xml');$script:disabled=@();$script:deleteCalls=0;$script:deny=$false
function Get-NetAdapter {param([switch]$IncludeHidden) return $script:adapters}
function Get-WirelessProfileFiles {return $script:files}
function Remove-WirelessProfiles {$script:deleteCalls++;if($script:deny){return 5};$script:files=@();return 0}
function Disable-NetAdapter {
 [CmdletBinding(SupportsShouldProcess=$true)]param([Parameter(ValueFromPipeline=$true)]$InputObject)
 process{if($InputObject.InterfaceGuid -ne 'wifi'){throw 'Attempted to disable non-wireless adapter'};$InputObject.InterfaceAdminStatus=2;$script:disabled+=$InputObject.InterfaceGuid}
}
$result=@(Invoke-WirelessCleanup)
if($files.Count -ne 0 -or $disabled.Count -ne 1 -or $adapters[0].InterfaceAdminStatus -ne 1){throw 'Cleanup selection failed'}
$inspection=@(Get-WirelessInspection)
if(@($inspection|Where-Object {$_.Conclusion -ne '通过'}).Count){throw 'Post-cleanup inspection failed'}
$null=Invoke-WirelessCleanup
if($deleteCalls -ne 1 -or $disabled.Count -ne 1){throw 'Repeated cleanup is not idempotent'}
$script:files=@('policy.xml');$script:deny=$true
$result=@(Invoke-WirelessCleanup)
if($result[0].Status -ne '失败/需复核' -or $result[0].After -ne 1){throw 'Policy failure misreported'}
$inspection=@(Get-WirelessInspection)
if($inspection[0].Conclusion -ne '异常'){throw 'Remaining profile misreported'}
function Get-WirelessProfileFiles {throw 'Access denied fixture'}
$inspection=@(Get-WirelessInspection)
if($inspection[0].Conclusion -ne '需复核'){throw 'Unreadable store reported empty'}
Write-Host 'PASS: hardware classification, wired preservation, profile deletion, disable, repeat, residual and access failure'
