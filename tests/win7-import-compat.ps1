param(
    [Parameter(Mandatory = $true)]
    [string[]]$Path,

    [string]$Dumpbin
)

$ErrorActionPreference = 'Stop'

if (-not $Dumpbin) {
    $dumpbinCommand = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($dumpbinCommand) {
        $Dumpbin = $dumpbinCommand.Source
    } else {
        $roots = @(
            "$env:ProgramFiles\Microsoft Visual Studio",
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio"
        ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

        $Dumpbin = $roots |
            ForEach-Object {
                Get-ChildItem -LiteralPath $_ -Recurse -Filter dumpbin.exe -File -ErrorAction SilentlyContinue
            } |
            Sort-Object FullName -Descending |
            Select-Object -First 1 -ExpandProperty FullName
    }
}

if (-not $Dumpbin -or -not (Test-Path -LiteralPath $Dumpbin)) {
    throw 'dumpbin.exe was not found. Pass its Visual Studio path with -Dumpbin.'
}

# These imports are absent from Windows 7 SP1 and prevent the process loader
# from reaching the program entry point.
$blockedImports = @(
    'CreateFile2',
    'GetSystemTimePreciseAsFileTime',
    'GetTempPath2A',
    'GetTempPath2W',
    'SetThreadDescription'
)

$failed = $false
foreach ($item in $Path) {
    $resolved = (Resolve-Path -LiteralPath $item).Path
    $imports = & $Dumpbin /nologo /imports $resolved 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "dumpbin could not inspect: $resolved`n$imports"
    }

    $found = @($blockedImports | Where-Object { $imports -match "(?m)\b$([regex]::Escape($_))\b" })
    if ($found.Count -gt 0) {
        $failed = $true
        Write-Host "[FAIL] $resolved"
        Write-Host "       Unsupported Windows 7 imports: $($found -join ', ')"
    } else {
        Write-Host "[PASS] $resolved"
    }
}

if ($failed) {
    exit 1
}

Write-Host 'All targets passed the Windows 7 static import check.'
