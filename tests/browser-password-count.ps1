param(
    [Parameter(Mandatory=$true)]
    [string]$InspectorPath
)

$ErrorActionPreference='Stop'
if(!(Test-Path -LiteralPath $InspectorPath)){throw "找不到现场检查程序：$InspectorPath"}

$work=Join-Path $env:TEMP 'SecurityRemediatorBrowserPasswordTest'
if(Test-Path -LiteralPath $work){Remove-Item -LiteralPath $work -Recurse -Force}
New-Item -ItemType Directory -Path $work | Out-Null

try {
    $empty=Join-Path $work 'empty.db'
    $saved=Join-Path $work 'saved.db'
    $create="import sqlite3,sys; db=sqlite3.connect(sys.argv[1]); db.execute('create table logins(password_value blob)'); n=int(sys.argv[2]); db.executemany('insert into logins(password_value) values (?)', [(sqlite3.Binary(b'encrypted'),)]*n); db.commit(); db.close()"
    & python -c $create $empty 0
    if($LASTEXITCODE -ne 0){throw '无法创建空密码库测试样本。'}
    & python -c $create $saved 1
    if($LASTEXITCODE -ne 0){throw '无法创建含密码条目的测试样本。'}

    $emptyResult=& $InspectorPath /count-chromium-logins $empty
    if($LASTEXITCODE -ne 0 -or ($emptyResult -join '').Trim() -ne '0'){throw '空密码库没有返回 0。'}

    $savedResult=& $InspectorPath /count-chromium-logins $saved
    if($LASTEXITCODE -ne 0 -or ($savedResult -join '').Trim() -ne '1'){throw '含一条密码记录的密码库没有返回 1。'}

    Write-Host 'PASS：现场检查程序能区分无保存密码和存在保存密码。'
}
finally {
    if(Test-Path -LiteralPath $work){Remove-Item -LiteralPath $work -Recurse -Force}
}
