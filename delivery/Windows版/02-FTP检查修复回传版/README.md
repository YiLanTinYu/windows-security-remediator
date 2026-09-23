# Windows FTP 静默检查修复回传版使用说明

入口：`ftp-check-repair.exe`
版本：2.0.3
公开模板接收端：`192.0.2.10:12221`（文档保留地址，部署前必须替换）

## 使用场景

用于网管系统以 SYSTEM 或已提权管理员身份静默推送。单个 EXE 会自动完成修复前检查、修复、复检、生成报告和被动 FTP 上传，不安装服务、不创建开机启动项，也不会周期性重复运行；是否重复下发由网管平台决定。

## 推荐测试顺序

```powershell
# 第一步：只检查并回传，确认网络和 FTP 正常，不修改终端
.\ftp-check-repair.exe /audit-only

# 第二步：确认回传成功后，执行完整检查修复和回传
.\ftp-check-repair.exe
```

临时改用另一个接收地址：

```powershell
.\ftp-check-repair.exe /server=192.168.1.10:12221 /audit-only
.\ftp-check-repair.exe /server=192.168.1.10:12221
```

`/server` 只修改本次连接地址，不修改 EXE 内置值；临时接收端必须使用与成品内置配置相同的 FTP 账号和密码。

仅在本机运行：

```powershell
# 只检查、不修复、不上传
.\ftp-check-repair.exe /audit-only /local-only

# 不上传，但仍自动修复
.\ftp-check-repair.exe /local-only
```

## 输出和上传判断

上传失败时，本目录保留 HTML、JSON 和 `upload-status.json`。判断 FTP 是否成功应查看状态文件中的 `uploaded` 字段：

- `"uploaded": true`：上传成功。
- `"uploaded": false`：上传失败，查看同文件中的错误说明。

只检查发现异常时退出码可能为 `5`，但报告仍可能已经上传，所以不能仅凭退出码判断 FTP 成败。

| 退出码 | 含义 |
|---:|---|
| 0 | 本地流程和上传成功 |
| 1 | 本地修复或报告流程不完整 |
| 2 | 参数或 FTP 配置错误 |
| 3 | 权限不足 |
| 5 | 审计发现异常，报告可能已成功上传 |
| 6 | 本地修复成功，但上传失败 |
| 7 | 本地操作存在异常且上传失败 |

## 回传失败现场排错

先在程序所在目录确认本地报告和上传状态，不要反复运行覆盖现场判断：

```powershell
Get-ChildItem .\verification-report_*.html, .\verification-report_*.json, .\upload-status.json |
  Sort-Object LastWriteTime -Descending |
  Select-Object LastWriteTime, Length, Name
Get-Content .\upload-status.json
```

把下面的 `<FTP_SERVER>` 和端口替换为运维下发值。Windows 10/11 可直接检查控制端口：

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

按错误阶段判断：

- 控制端口超时或无路由：检查终端 IP/网关、VLAN、交换机 ACL、终端 CEMS/防火墙、接收端允许来源网段。
- `Connection refused`：接收端地址可达，但 FTP 接收进程未监听该端口，或主机防火墙主动拒绝。
- FTP `530`：已经到达接收端，检查成品内置账号密码是否与接收端一致；不要在现场命令行中输入或显示密码。
- FTP `425`、`426`，或登录后传输超时：控制连接正常，但被动数据端口未放通；检查接收端被动端口范围及两端防火墙/ACL。
- 同一程序只有部分终端失败：比较失败终端与成功终端的源 IP、路由、CEMS 策略和接收端允许网段，不要先重新构建程序。

将 `upload-status.json`、上述端口测试结果、`ipconfig /all` 和失败时间交给接收端管理员。不要发送包含真实 FTP 密码的截图或命令记录。

## 部署要求

- FTP 接收端必须监听控制端口并开放配置的被动端口范围。
- 防火墙允许来源应覆盖实际终端地址或最小必要网段。
- 普通 FTP 不加密，只能在受控内网使用。
- FTP 凭据已写入正式 EXE，不会写入 README、报告或状态文件。
- 批量推送前先选择少量终端运行 `/audit-only`，核对服务端报告目录后再扩大范围。

如果只有部分终端上传失败，而同一程序在其他终端成功，应优先比较失败终端的路由、ARP、CEMS/防火墙策略、VLAN和交换机访问控制，不要先重新构建程序。
