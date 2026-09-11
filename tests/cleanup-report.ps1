param([string]$ScriptPath)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($ScriptPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse failed'}
foreach($name in @('E','Row','SaveReport')){$fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true);Invoke-Expression $fn.Extent.Text}
$report=Join-Path $env:TEMP ('cleanup-report-test-'+[Guid]::NewGuid().ToString('N')+'.html')
$rows=New-Object System.Collections.ArrayList;$identity=[pscustomobject]@{Name='TestUser'};$ip='192.0.2.1';$mac='00-00-00-00-00-01'
try{Row 'Test <browser>' 2 2 0 '已清空' 'synthetic test';Row 'USB' 1 0 '?' '失败/需复核' 'access denied';SaveReport
 $html=[IO.File]::ReadAllText($report)
 foreach($expected in @('Test &lt;browser&gt;','临时清理报告','待现场检查复核','192.0.2.1','失败/需复核','删除数量')){if(!$html.Contains($expected)){throw 'report field missing'}}
 Write-Host 'PASS: temporary report metadata, outcome rows and escaping'
}finally{Remove-Item -LiteralPath $report -Force -ErrorAction SilentlyContinue}
