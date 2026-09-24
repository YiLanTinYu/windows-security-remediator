param([Parameter(Mandatory=$true)][string]$SourceRoot)

$ErrorActionPreference='Stop'
$windowsFirewall=[IO.File]::ReadAllText((Join-Path $SourceRoot 'src\firewall_remediation.cpp'))
$windowsAudit=[IO.File]::ReadAllText((Join-Path $SourceRoot 'src\audit_core.cpp'))
$windowsLegacy=[IO.File]::ReadAllText((Join-Path $SourceRoot 'src\main.cpp'))
$kylinPlan=[IO.File]::ReadAllText((Join-Path $SourceRoot 'kylin-security-remediator\internal\firewall\plan.go'))
$content=($windowsFirewall,$windowsAudit,$windowsLegacy,$kylinPlan) -join "`n"

foreach($activePattern in @('{136, NET_FW_IP_PROTOCOL_TCP','{136, NET_FW_IP_PROTOCOL_UDP','L"TCP-136"},','L"UDP-136"},')){
    if($content.Contains($activePattern)){throw "Managed port policy still contains active pattern $activePattern"}
}
$requiredSegment=$kylinPlan.Substring($kylinPlan.IndexOf('var requiredRules'),$kylinPlan.IndexOf('var legacyRules')-$kylinPlan.IndexOf('var requiredRules'))
if($requiredSegment.Contains('Port: 136')){throw 'Kylin required rules still include port 136'}
foreach($legacyName in @('SecurityRemediator - Block TCP-136','SecurityRemediator - Block UDP-136')){
    if(!$content.Contains($legacyName)){throw "Legacy cleanup is missing $legacyName"}
}
if(!$kylinPlan.Contains('legacyCleanupPlan')){throw 'Kylin legacy cleanup plan is missing'}
foreach($required in @('TCP-22','TCP-135','UDP-137','UDP-138','TCP-139','TCP-445','TCP-3389','UDP-3389')){
    if(!$content.Contains($required)){throw "Managed port policy is missing $required"}
}

Write-Host 'managed port policy test passed'
