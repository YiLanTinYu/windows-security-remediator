param([Parameter(Mandatory=$true)][string]$InspectorPath,[Parameter(Mandatory=$true)][string]$VerifierPath)
$ErrorActionPreference='Stop'
$work=Join-Path $env:TEMP ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $work 'Default') -Force|Out-Null
try{
    $db=Join-Path $work 'Default\Login Data'
    & python -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('create table logins(origin_url text,username_value text,password_value blob)'); c.execute('insert into logins values(?,?,?)',('https://example.test/?a=1&b=2',sys.argv[2],b'PASSWORD_SENTINEL')); c.execute('insert into logins values(?,?,?)',('https://excluded.test','excluded',b'')); c.commit(); c.close()" $db '测试<账号>"'
    if($LASTEXITCODE){throw 'fixture failed'}
    [Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
    $json=(& $InspectorPath /list-chromium-logins $db) -join ''
    if($LASTEXITCODE){throw 'reader failed'}
    $rows=@($json|ConvertFrom-Json)
    if($rows.Count -ne 1 -or $rows[0].account -ne '测试<账号>"' -or $rows[0].website -ne 'https://example.test/?a=1&b=2'){throw 'metadata mismatch'}
    if($json.Contains('PASSWORD_SENTINEL') -or $json.Contains('excluded')){throw 'unexpected secret or empty password record'}
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($VerifierPath,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'script parse failed'}
    foreach($name in @('AddBrowserRow','AddAccountRow','AddChromiumSavedPasswords','EncodeHtml')){
        $fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
        Invoke-Expression $fn.Extent.Text
    }
    $script:accountRows=@();$script:browserRows=@()
    AddChromiumSavedPasswords 'Test Browser' $work $InspectorPath
    if($accountRows.Count -ne 1 -or $browserRows[0].Conclusion -ne '异常'){throw 'report integration failed'}
    if((EncodeHtml $accountRows[0].Account) -ne '测试&lt;账号&gt;&quot;'){throw 'HTML escaping failed'}
    Write-Host 'PASS: website/account metadata, Unicode, filtering, no password output, report integration and HTML escaping'
}finally{if([IO.Path]::GetDirectoryName($work) -eq $env:TEMP.TrimEnd('\')){Remove-Item -LiteralPath $work -Recurse -Force}}
