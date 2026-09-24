param(
    [Parameter(Mandatory=$true)][string]$ScriptPath,
    [Parameter(Mandatory=$true)][string]$DeliveryDirectory
)

$ErrorActionPreference='Stop'

function Get-PeMachine([string]$Path) {
    $stream=[IO.File]::OpenRead($Path)
    try {
        $reader=New-Object IO.BinaryReader($stream)
        $stream.Position=0x3c
        $peOffset=$reader.ReadInt32()
        $stream.Position=$peOffset+4
        return $reader.ReadUInt16()
    } finally {
        $stream.Dispose()
    }
}

$script=[IO.File]::ReadAllText($ScriptPath)
if($script -notmatch [regex]::Escape("Join-Path `$base 'record-cleaner-x64.exe'")) {
    throw 'The cleanup script does not select record-cleaner-x64.exe on 64-bit Windows'
}
if($script -notmatch [regex]::Escape('& $usbCleaner /remove-usb-history')) {
    throw 'USB removal does not use the architecture-specific cleanup helper'
}
if($script -notmatch [regex]::Escape('if(!$usbCleaner)')) {
    throw 'The cleanup script does not fail clearly when the x64 helper is missing'
}

$entry=Join-Path $DeliveryDirectory 'record-cleaner.exe'
$native=Join-Path $DeliveryDirectory 'record-cleaner-x64.exe'
if(!(Test-Path -LiteralPath $entry)){throw 'Delivery is missing record-cleaner.exe'}
if(!(Test-Path -LiteralPath $native)){throw 'Delivery is missing record-cleaner-x64.exe'}
if((Get-PeMachine $entry) -ne 0x014c){throw 'record-cleaner.exe must remain the x86 universal entry point'}
if((Get-PeMachine $native) -ne 0x8664){throw 'record-cleaner-x64.exe must be an x64 executable'}

Write-Host 'cleanup native helper test passed'
