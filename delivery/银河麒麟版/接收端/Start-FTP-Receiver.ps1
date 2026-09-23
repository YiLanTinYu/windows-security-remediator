#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

function Read-Required([string]$Prompt) {
    do {
        $value = ([string](Read-Host $Prompt)).Trim()
        if ([string]::IsNullOrWhiteSpace($value)) {
            Write-Warning "$Prompt 不能为空，请重新输入。"
        }
    } while ([string]::IsNullOrWhiteSpace($value))
    return $value
}

function Read-ReceiverConfig([string]$Path) {
    $values = @{}
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-Warning "未找到配置文件：$Path。缺少的项目将在本次运行中提示输入。"
        return $values
    }

    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $Path) {
        $lineNumber++
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith("#")) {
            continue
        }
        $separator = $trimmed.IndexOf("=")
        if ($separator -lt 1) {
            Write-Warning "配置文件第 $lineNumber 行格式无效，已忽略：$trimmed"
            continue
        }
        $key = $trimmed.Substring(0, $separator).Trim().ToUpperInvariant()
        $value = $trimmed.Substring($separator + 1).Trim()
        if ($values.ContainsKey($key)) {
            Write-Warning "配置项 $key 重复，使用最后一个值。"
        }
        $values[$key] = $value
    }
    return $values
}

function Read-IPv4([string]$InitialValue) {
    $value = ([string]$InitialValue).Trim()
    while ($true) {
        $parsed = $null
        if ([Net.IPAddress]::TryParse($value, [ref]$parsed) -and
            $parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
            return $value
        }
        if ([string]::IsNullOrWhiteSpace($value)) {
            Write-Warning "配置文件未填写 PASSIVE_IP。"
        } else {
            Write-Warning ("被动模式地址 [{0}] 不是有效的 IPv4 地址。" -f $value)
        }
        $value = ([string](Read-Host "请重新输入本机 IPv4 地址（仅本次有效）")).Trim()
    }
}

function Read-PortValue([string]$Name, [string]$InitialValue) {
    $value = ([string]$InitialValue).Trim()
    while ($true) {
        $port = 0
        if ([int]::TryParse($value, [ref]$port) -and $port -ge 1 -and $port -le 65535) {
            return $port
        }
        if ([string]::IsNullOrWhiteSpace($value)) {
            Write-Warning "配置文件未填写 $Name。"
        } else {
            Write-Warning ("{0} 的值 [{1}] 无效，必须是 1 到 65535 之间的整数。" -f $Name, $value)
        }
        $value = ([string](Read-Host "请重新输入 $Name（仅本次有效）")).Trim()
    }
}

function ConvertTo-RemoteAddressList([string]$Value) {
    $addresses = [Collections.Generic.List[string]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($part in ($Value -split '[,，;；\s]+')) {
        $address = $part.Trim()
        if ([string]::IsNullOrWhiteSpace($address)) {
            continue
        }
        $addressParts = @($address.Split('/'))
        $parsedAddress = $null
        $prefixLength = 0
        $validPrefix = $addressParts.Count -eq 1 -or
            ($addressParts.Count -eq 2 -and
             [int]::TryParse($addressParts[1], [ref]$prefixLength) -and
             $prefixLength -ge 0 -and $prefixLength -le 32)
        if (-not $validPrefix -or
            -not [Net.IPAddress]::TryParse($addressParts[0], [ref]$parsedAddress) -or
            $parsedAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
            throw "无效的终端 IP 或网段：$address"
        }
        if ($seen.Add($address)) {
            $addresses.Add($address)
        }
    }
    if ($addresses.Count -eq 0) {
        throw "至少需要填写一个允许回传的终端 IP 或网段。"
    }
    return $addresses.ToArray()
}

function Read-RemoteAddressList([string]$InitialValue) {
    $value = ([string]$InitialValue).Trim()
    while ($true) {
        try {
            return @(ConvertTo-RemoteAddressList $value)
        }
        catch {
            Write-Warning $_.Exception.Message
            $value = Read-Required "请重新输入允许回传的终端 IP 或网段，多个值用逗号分隔（仅本次有效）"
        }
    }
}

function Test-StrongPassword([string]$Password) {
    if ($Password.Length -lt 15) {
        return $false
    }
    $upper = $false
    $lower = $false
    $digit = $false
    $special = $false
    foreach ($character in $Password.ToCharArray()) {
        if ([char]::IsUpper($character)) {
            $upper = $true
        } elseif ([char]::IsLower($character)) {
            $lower = $true
        } elseif ([char]::IsDigit($character)) {
            $digit = $true
        } else {
            $special = $true
        }
    }
    return $upper -and $lower -and $digit -and $special
}

function Read-StrongPassword {
    while ($true) {
        $secure = Read-Host "请输入强密码（至少15位，含大小写字母、数字和特殊字符）" -AsSecureString
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try {
            $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
            if (Test-StrongPassword $plain) {
                return $secure
            }
        }
        finally {
            if ($pointer -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
            }
        }
        Write-Warning "密码不符合强度要求，请重新输入。"
    }
}

function Resolve-UploadDirectory([string]$InitialValue) {
    $value = ([string]$InitialValue).Trim()
    while ($true) {
        if ([string]::IsNullOrWhiteSpace($value)) {
            Write-Warning "配置文件未填写 REPORT_DIRECTORY。"
            $value = ([string](Read-Host "请重新输入报告保存目录（仅本次有效）")).Trim()
            continue
        }
        try {
            if ([IO.Path]::IsPathRooted($value)) {
                $path = [IO.Path]::GetFullPath($value)
            } else {
                $path = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $value))
            }
            [IO.Directory]::CreateDirectory($path) | Out-Null
            return $path
        }
        catch {
            Write-Warning ("报告目录 [{0}] 无效或无法创建：{1}" -f $value, $_.Exception.Message)
            $value = ([string](Read-Host "请重新输入报告保存目录（仅本次有效）")).Trim()
        }
    }
}

$receiver = Join-Path $PSScriptRoot "report-receiver-windows-amd64.exe"
if (-not (Test-Path -LiteralPath $receiver -PathType Leaf)) {
    throw "未找到接收程序：$receiver"
}

$configPath = Join-Path $PSScriptRoot "FTP-Receiver.conf"
$config = Read-ReceiverConfig $configPath
$passiveIp = Read-IPv4 $config["PASSIVE_IP"]
$controlPort = Read-PortValue "CONTROL_PORT" $config["CONTROL_PORT"]
$passiveStart = Read-PortValue "PASSIVE_PORT_START" $config["PASSIVE_PORT_START"]
$passiveEnd = Read-PortValue "PASSIVE_PORT_END" $config["PASSIVE_PORT_END"]
while ($passiveEnd -lt $passiveStart) {
    Write-Warning "被动端口结束值 $passiveEnd 不能小于起始值 $passiveStart。"
    $correctedPassiveEnd = Read-Host "请重新输入 PASSIVE_PORT_END（仅本次有效）"
    $passiveEnd = Read-PortValue "PASSIVE_PORT_END" $correctedPassiveEnd
}
$allowedRemote = @(Read-RemoteAddressList $config["ALLOWED_REMOTE"])
$uploadDir = Resolve-UploadDirectory $config["REPORT_DIRECTORY"]

Write-Host "已读取非敏感配置：$configPath" -ForegroundColor Cyan
Write-Host ("监听地址：{0}:{1}" -f $passiveIp, $controlPort)
Write-Host "被动端口：$passiveStart-$passiveEnd"
Write-Host "允许来源：$($allowedRemote -join ', ')"
Write-Host "报告目录：$uploadDir"

$username = Read-Required "请输入仅上传账号"
$securePassword = Read-StrongPassword

$credential = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
try {
    $env:KYLIN_REPORT_FTP_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($credential)

    $controlRule = "KylinReportFTP-Control"
    $passiveRule = "KylinReportFTP-Passive"
    Get-NetFirewallRule -Name $controlRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Get-NetFirewallRule -Name $passiveRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule

    $controlRuleParameters = @{
        Name = $controlRule
        DisplayName = "Kylin report FTP control"
        Direction = "Inbound"
        Action = "Allow"
        Protocol = "TCP"
        LocalPort = $controlPort
        RemoteAddress = $allowedRemote
    }
    New-NetFirewallRule @controlRuleParameters | Out-Null

    $passiveRuleParameters = @{
        Name = $passiveRule
        DisplayName = "Kylin report FTP passive data"
        Direction = "Inbound"
        Action = "Allow"
        Protocol = "TCP"
        LocalPort = "$passiveStart-$passiveEnd"
        RemoteAddress = $allowedRemote
    }
    New-NetFirewallRule @passiveRuleParameters | Out-Null

    Write-Host "接收服务已准备启动。请保持本窗口开启；按 Ctrl+C 可停止。" -ForegroundColor Green
    $receiverArguments = @(
        "--listen", "0.0.0.0:$controlPort",
        "--passive-ip", $passiveIp,
        "--passive-start", $passiveStart,
        "--passive-end", $passiveEnd,
        "--upload-dir", $uploadDir,
        "--user", $username,
        "--password-env", "KYLIN_REPORT_FTP_PASSWORD"
    )
    & $receiver @receiverArguments
    if ($LASTEXITCODE -ne 0) {
        throw "接收程序退出，代码：$LASTEXITCODE"
    }
}
finally {
    $env:KYLIN_REPORT_FTP_PASSWORD = $null
    if ($credential -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($credential)
    }
}
