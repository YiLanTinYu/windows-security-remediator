param([Parameter(Mandatory=$true)][string]$ScriptPath)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($ScriptPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'cleanup script parse failed'}
$functionAst=$ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Invoke-IECleanupStore'
},$true)
if(!$functionAst){throw 'Invoke-IECleanupStore function missing'}
Invoke-Expression $functionAst.Extent.Text

$fixture=Join-Path $env:TEMP ('ie-cleanup-fixture-'+[Guid]::NewGuid().ToString('N')+'.ps1')
try{
    @'
param([string]$Mode)
if($Mode -eq '/inspect'){ '3 0 3'; exit 0 }
if($Mode -eq '/clear'){ '3 2 1'; exit 0 }
if($Mode -eq '/error'){ [Console]::Error.WriteLine('access denied'); exit 6 }
exit 2
'@ | Set-Content -LiteralPath $fixture -Encoding UTF8

    $inspected=Invoke-IECleanupStore -CleanerPath $fixture -Argument '/inspect' -Label 'IE Storage2'
    if($inspected.Before -ne 3 -or $inspected.Removed -ne 0 -or
       $inspected.After -ne 3 -or $inspected.Status -ne '待确认'){
        throw 'inspection result mismatch'
    }
    $cleaned=Invoke-IECleanupStore -CleanerPath $fixture -Argument '/clear' -Label 'IE Storage2'
    if($cleaned.Before -ne 3 -or $cleaned.Removed -ne 2 -or
       $cleaned.After -ne 1 -or $cleaned.Status -ne '未清空'){
        throw 'post-clean rescan result mismatch'
    }
    $failed=Invoke-IECleanupStore -CleanerPath $fixture -Argument '/error' -Label 'IE Storage2'
    if($failed.Status -ne '失败/需复核' -or $failed.After -ne '?'){
        throw 'read failure was not marked for review'
    }
    Write-Host 'PASS: IE cleanup reports inspect, remaining records and read failure accurately'
}finally{
    Remove-Item -LiteralPath $fixture -Force -ErrorAction SilentlyContinue
}
