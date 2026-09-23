param(
    [string]$Server = "192.0.2.10:8443",
    [string]$DataDir = "$env:ProgramData\SecurityInspectionReportServer"
)
$ErrorActionPreference = "Stop"
$key = (Get-Content -Raw -LiteralPath (Join-Path $DataDir "upload.key")).Trim()
$pin = (Get-Content -Raw -LiteralPath (Join-Path $DataDir "server-cert-sha256.txt")).Trim()
if ($key -notmatch '^[0-9A-Fa-f]{64}$') { throw "upload.key 格式错误" }
if ($pin -notmatch '^[0-9A-Fa-f]{64}$') { throw "证书指纹格式错误" }
$cmake = Join-Path ${env:ProgramFiles} "Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
$source = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
foreach ($arch in @("x86", "x64")) {
    $build = Join-Path $env:TEMP "SecurityRemediator-build-report-$arch"
    $vcvars = Join-Path ${env:ProgramFiles} "Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat"
    $command = "call `"$vcvars`" $arch && `"$cmake`" -S `"$source`" -B `"$build`" -G Ninja -DCMAKE_BUILD_TYPE=Release -DSR_UPLOAD_KEY_HEX=$key -DSR_SERVER_CERT_SHA256=$pin -DSR_DEFAULT_SERVER=$Server && `"$cmake`" --build `"$build`" --target remote-inspector remediator-inspector"
    & cmd.exe /d /c $command
    if ($LASTEXITCODE -ne 0) { throw "$arch 构建失败，退出码 $LASTEXITCODE" }
}
Write-Host "32位和64位客户端均已绑定服务端 $Server。"
