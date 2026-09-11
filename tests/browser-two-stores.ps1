param([string]$InspectorPath,[string]$VerifierPath)
$ErrorActionPreference='Stop'
$work=Join-Path $env:TEMP ('two-stores-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $work 'Default') -Force|Out-Null
try{
 foreach($name in @('Login Data','Login Data For Account')){
  & python -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('create table logins(origin_url text,username_value text,password_value blob)'); c.execute('insert into logins values(?,?,?)',('https://example.test','test',b'synthetic')); c.commit();c.close()" (Join-Path $work ('Default\'+$name))
  if($LASTEXITCODE){throw 'fixture failed'}
 }
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($VerifierPath,[ref]$tokens,[ref]$errors)
 foreach($name in @('AddBrowserRow','AddAccountRow','AddChromiumSavedPasswords')){$fn=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true);Invoke-Expression $fn.Extent.Text}
 $script:browserRows=@();$script:accountRows=@();AddChromiumSavedPasswords 'Test' $work $InspectorPath
 if($accountRows.Count -ne 2 -or $browserRows.Count -ne 2){throw 'Both stores must be reported'}
 if(!(@($browserRows.Scope) -contains 'Default / Login Data For Account')){throw 'Account store label missing'}
 Write-Host 'PASS: both local and account password databases reported separately'
}finally{Remove-Item -LiteralPath $work -Recurse -Force}
