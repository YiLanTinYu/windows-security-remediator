param(
    [Parameter(Mandatory=$true)]
    [string]$ExePath
)

$ErrorActionPreference='Stop'
$stateFile=Join-Path $env:ProgramData 'SecurityRemediator\backup.state'
if(!(Test-Path -LiteralPath $ExePath)){throw "找不到待测试程序：$ExePath"}
if(!(Test-Path -LiteralPath $stateFile)){throw "测试前提不满足：不存在初始备份 $stateFile"}

function Snapshot {
    $item=Get-Item -LiteralPath $stateFile
    New-Object PSObject -Property @{
        Hash=(Get-FileHash -Algorithm SHA256 -LiteralPath $stateFile).Hash
        LastWriteUtc=$item.LastWriteTimeUtc.Ticks
    }
}

function Assert-Unchanged($before,[string]$operation) {
    $after=Snapshot
    if($before.Hash -ne $after.Hash -or $before.LastWriteUtc -ne $after.LastWriteUtc){
        throw "$operation 改写了已有初始备份。"
    }
}

$resultDir=Join-Path $env:TEMP 'SecurityRemediatorBackupTest'
if(!(Test-Path -LiteralPath $resultDir)){New-Item -ItemType Directory -Path $resultDir | Out-Null}

$baseline=Snapshot
$audit=Start-Process -FilePath $ExePath -ArgumentList @('/audit','/log-dir',$resultDir) -Wait -PassThru -WindowStyle Hidden
if($audit.ExitCode -ne 0 -and $audit.ExitCode -ne 5){throw "audit 返回了非预期退出码：$($audit.ExitCode)"}
Assert-Unchanged $baseline '/audit'

Start-Sleep -Milliseconds 1100
$apply=Start-Process -FilePath $ExePath -ArgumentList @('/apply','/log-dir',$resultDir) -Wait -PassThru -WindowStyle Hidden
if($apply.ExitCode -ne 0 -and $apply.ExitCode -ne 4){throw "apply 返回了非预期退出码：$($apply.ExitCode)"}
Assert-Unchanged $baseline '重复 /apply'

Write-Host 'PASS：/audit 和重复 /apply 均未改写已有初始备份。'
