# Windows FTP 回传失败排错

本目录只提供现场排错说明，不包含 Windows FTP 推送程序。排错时不要在命令、截图或记录中显示 FTP 密码。

## 1. 查看本地报告和上传状态

在 FTP 程序所在目录打开 PowerShell，运行：

```powershell
Get-ChildItem .\verification-report_*.html, .\verification-report_*.json, .\upload-status.json |
  Sort-Object LastWriteTime -Descending |
  Select-Object LastWriteTime, Length, Name
Get-Content .\upload-status.json
```

- `"uploaded": true`：报告已上传。
- `"uploaded": false`：上传失败，继续查看同文件中的错误说明。
- 退出码 `5` 可能只表示审计发现异常，不能单独用来判断 FTP 是否上传成功。

## 2. 检查 FTP 控制端口

将 `<FTP_SERVER>` 和 `12221` 替换为运维下发的实际接收端地址和控制端口。Windows 10/11 运行：

```powershell
Test-NetConnection -ComputerName <FTP_SERVER> -Port 12221 -InformationLevel Detailed
```

Windows 7 没有 `Test-NetConnection` 时，在 PowerShell 中运行：

```powershell
$server = '<FTP_SERVER>'
$port = 12221
ping $server
route print
arp -a
$tcp = New-Object System.Net.Sockets.TcpClient
try {
    $tcp.Connect($server, $port)
    'FTP 控制端口连接成功'
} catch {
    'FTP 控制端口连接失败：' + $_.Exception.Message
} finally {
    $tcp.Close()
}
```

## 3. 按错误阶段判断

- 控制端口超时或无路由：检查终端 IP/网关、VLAN、交换机 ACL、终端 CEMS/防火墙、接收端允许来源网段。
- `Connection refused`：地址可达，但接收端未监听该端口，或主机防火墙主动拒绝。
- FTP `530`：已经达到接收端，检查程序内置账号密码是否与接收端一致。
- FTP `425`、`426` 或登录后传输超时：控制连接正常，但被动数据端口未放通；检查接收端被动端口范围及两端防火墙/ACL。
- 同一程序只有部分终端失败：比较失败终端与成功终端的源 IP、路由、ARP、CEMS 策略和接收端允许网段，不要首先重新构建程序。

## 4. 交给接收端管理员的信息

保留并提供：

- `upload-status.json`
- 控制端口测试结果
- `ipconfig /all`
- 准确的失败时间

不要发送含有真实 FTP 密码的截图或命令记录。
