param([string]$InspectorPath,[string]$VerifierPath)
$ErrorActionPreference='Stop'
$work=Join-Path $env:TEMP ('empty-browser-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $work 'Default') -Force|Out-Null
try{
 $db=Join-Path $work 'Default\Login Data'
 & python -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('create table logins(origin_url text,username_value text,password_value blob)'); c.commit(); c.close()" $db
 if($LASTEXITCODE){throw 'fixture failed'}
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($VerifierPath,[ref]$tokens,[ref]$errors)
 foreach($name in @('AddBrowserRow','AddAccountRow','AddChromiumSavedPasswords')){
  $fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true);Invoke-Expression $fn.Extent.Text
 }
 $script:browserRows=@();$script:accountRows=@()
 AddChromiumSavedPasswords 'Test' $work $InspectorPath
 if($accountRows.Count -ne 0){throw ('Empty database produced fake account rows: '+$accountRows.Count)}
 if($browserRows[0].Actual -notmatch '0'){throw 'Empty database count is not zero'}
 Write-Host 'PASS: empty database has zero account rows and zero saved passwords'
}finally{Remove-Item -LiteralPath $work -Recurse -Force}
