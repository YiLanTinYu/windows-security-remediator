param([string]$CleanerPath)
$ErrorActionPreference='Stop'
$work=Join-Path $env:TEMP ('cleanup-fixture-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work|Out-Null
try{
 $db=Join-Path $work 'test.db'
 & python -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('create table logins(password_value blob)'); c.executemany('insert into logins values(?)',[(b'synthetic',),(b'',),(None,)]); c.execute('create table unrelated(value text)'); c.execute('insert into unrelated values(?)',('keep',)); c.commit()" $db
 if($LASTEXITCODE){throw 'fixture failed'}
 $result=(& $CleanerPath /clear-chromium $db) -join '';if($LASTEXITCODE -ne 0 -or $result.Trim() -ne '1'){throw 'delete count failed'}
 & python -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); assert c.execute('select count(*) from logins').fetchone()[0]==2; assert c.execute('select value from unrelated').fetchone()[0]=='keep'" $db
 if($LASTEXITCODE){throw 'data preservation failed'}
 $result=(& $CleanerPath /clear-chromium $db) -join '';if($LASTEXITCODE -ne 0 -or $result.Trim() -ne '0'){throw 'repeat failed'}
 & $CleanerPath /clear-chromium (Join-Path $work 'missing.db')|Out-Null;if($LASTEXITCODE -eq 0){throw 'missing database not rejected'}
 if(Test-Path (Join-Path $work 'missing.db')){throw 'missing database created'}
 Write-Host 'PASS: synthetic password removal, unrelated data preserved, repeat and missing database'
}finally{if([IO.Path]::GetDirectoryName($work) -eq $env:TEMP.TrimEnd('\')){Remove-Item -LiteralPath $work -Recurse -Force}}
