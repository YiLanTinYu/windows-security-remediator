param([string]$VerifierPath)
$ErrorActionPreference='Stop'
$source=[IO.File]::ReadAllText($VerifierPath)
$start=$source.IndexOf("ShowStep 'USB 存储设备注册表记录'")
$end=$source.IndexOf('function AddBrowserRow',$start)
$block=$source.Substring($start,$end-$start)
function ShowStep($s){}
function W($s){}
function V($s){return [string]$s}
function S($item,$expected,$actual,$conclusion){$script:result=@($actual,$conclusion)}
function Get-Item {
 if($script:scenario -eq 'missing'){throw (New-Object System.Management.Automation.ItemNotFoundException 'missing')}
 if($script:scenario -eq 'denied'){throw (New-Object UnauthorizedAccessException 'denied')}
 return [pscustomobject]@{PSPath='root'}
}
function Get-ChildItem {
 param($LiteralPath)
 if($script:scenario -eq 'missing'){throw (New-Object System.Management.Automation.ItemNotFoundException 'missing')}
 if($script:scenario -eq 'denied'){throw (New-Object UnauthorizedAccessException 'denied')}
 if($script:scenario -eq 'empty'){return}
 if($LiteralPath -eq 'device'){return [pscustomobject]@{PSPath='instance';PSChildName='instance'}}
 return [pscustomobject]@{PSPath='device';PSChildName='device'}
}
function Get-ItemProperty {return [pscustomobject]@{FriendlyName='fixture';DeviceDesc='fixture';Mfg='fixture'}}
foreach($scenario in @('missing','empty','present','denied')){
 $script:scenario=$scenario;$usbRows=@();$usbReadError='';$script:result=@()
 Invoke-Expression $block
 $expected=switch($scenario){'missing'{'通过'} 'empty'{'通过'} 'present'{'需复核'} 'denied'{'异常'}}
 if($result[1] -ne $expected){throw "$scenario expected $expected, got $($result[1])"}
 if($scenario -eq 'denied' -and !$usbReadError){throw 'Read failure detail missing'}
 if($scenario -in @('missing','empty') -and $usbReadError){throw 'Empty misreported as failure'}
 Write-Host "PASS: $scenario"
}
