# 银河麒麟报告 FTP 接收端使用说明

此目录实际运行在 Windows 报告接收电脑上，不在麒麟终端运行。它是一个可选的独立接收端启动包；如果现场已经使用 Windows 版 FTP 接收服务，麒麟客户端可以直接共用该服务，不需要再启动第二个接收端。

## 1. 必需文件

```text
report-receiver-windows-amd64.exe
Start-FTP-Receiver.cmd
Start-FTP-Receiver.ps1
FTP-Receiver.conf
```

四个文件必须在同一目录。接收电脑无需安装 Go、Python、Java、数据库或第三方 FTP 服务。

## 2. 启动

1. 用文本编辑器打开 `FTP-Receiver.conf`，核对地址、端口、允许来源和报告目录。
2. 双击 `Start-FTP-Receiver.cmd`，在 UAC 提示中选择“是”。
3. 按提示输入专用上传账号和密码；两项不会写入配置文件。
4. 保持窗口开启。关闭窗口或进程退出后，接收服务停止。

## 3. 配置项

```text
PASSIVE_IP=<客户端可以访问的接收电脑IPv4>
CONTROL_PORT=<FTP控制端口>
PASSIVE_PORT_START=<被动端口起始值>
PASSIVE_PORT_END=<被动端口结束值>
ALLOWED_REMOTE=<允许的终端IPv4或CIDR，可填写多个>
REPORT_DIRECTORY=<接收报告保存目录>
```

详细正确/错误示例已经写在 `FTP-Receiver.conf` 的每个参数上方。重要规则：

- 客户端 `FTP_HOST` 必须等于可访问的 `PASSIVE_IP`。
- 客户端 `FTP_PORT` 必须等于 `CONTROL_PORT`。
- 多个来源可用逗号、分号或空格分隔，例如 `192.0.2.0/24,198.51.100.0/24`。
- 不建议使用 `0.0.0.0/0`。
- `REPORT_DIRECTORY` 为相对路径时，以本接收端目录为基准；也可以填写 Windows 绝对路径。

配置错误时脚本会指出具体项目并允许本次重新输入；要永久生效仍需修改配置文件。

## 4. 防火墙和端口

启动脚本会为控制端口和整个被动端口范围创建受限来源的 Windows 入站规则。控制端口负责登录和上传指令，被动端口负责传输 HTML/JSON；两者都必须从客户端可达。客户端无需开放入站端口，也不需要 SSH。

检查监听状态：

```powershell
Get-NetTCPConnection -LocalPort <控制端口> -State Listen
```

客户端能够建立控制连接时应收到以 `220` 开头的 FTP 欢迎信息。`530` 表示账号认证失败；连接超时或 `no route to host` 发生在认证之前。

## 5. 报告目录和统一管理

接收目录可以同时存放 Windows 和麒麟的 `verification-report_*` HTML/JSON。接收完成后，在该目录使用 Windows 版 `04-报告管理工具` 完成去重和 Excel 汇总。

接收程序先写入临时文件，只有长度和内容校验通过才发布正式报告。中断或损坏的片段不会作为正式 HTML/JSON 使用。

普通 FTP 不加密，只限受控内网。账号应仅用于上传，允许来源应限制为实际终端地址或最小必要网段。
