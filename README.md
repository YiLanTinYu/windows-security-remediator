# Windows 高危端口静默修复工具

Security Remediator 是一个原生 Win32 静默修复程序，用于在 Windows 7 SP1、Windows 10 和 Windows 11 上关闭指定的高危入站端口及相关服务。

- 当前版本：`1.2.0.0`
- 作者：倚栏听雨
- 程序图标：蓝色安全盾牌、封闭网络端口和雨滴标识

## 当前修复内容

- 启用 Windows 防火墙的域、专用、公用配置文件。
- 创建入站阻断规则：TCP 22、135、136、139、445、3389；UDP 136、137、138、3389。
- 重复执行时复用正确规则；发现同名重复规则时，只清理本程序的精确规则名并重建一条标准规则。
- 停止并禁用 `LanmanServer`（Server）文件共享服务。
- 停止并禁用 `TermService`（远程桌面）服务。
- 禁止远程桌面连接。
- 禁用所有网卡的 NetBIOS over TCP/IP。
- 不停止 RPC 核心服务，不改变客户端出站网络连接。

## 运行方式

网管系统可以使用 SYSTEM 或已提权的 Administrators 组成员权限静默推送。普通用户不会弹出 UAC，也不能执行系统级修复。

```bat
remediator.exe              rem 默认检测并修复
remediator.exe /apply       rem 检测并修复
remediator.exe /audit       rem 只检测，不修改
remediator.exe /rollback    rem 恢复最近一次备份
remediator.exe /log-dir D:\SecurityLogs
```

程序不显示窗口结果，网管平台应读取退出码和结果文件。

## 日志和结果

默认情况下，日志和验证报告写入 `remediator.exe` 所在目录，不再写入 `C:\ProgramData`。程序只保留一个运行日志，验证脚本只保留一个离线 HTML 报告：

```text
remediator.log    程序运行日志（每次运行覆盖）
verification-report.html  验证报告（每次验证覆盖）
last-result.json   网管系统使用的结构化结果
result.txt         新手可直接阅读的中文摘要
```

运行 `verify-remediator.bat` 时，验证脚本会只读枚举以下注册表，并将中文列表直接写入 `verification-report.html`：

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`

验证报告包含网络名称、配置文件 GUID、网络类别、创建及最后连接时间，以及 USB
设备类型、实例 ID/序列号、友好名称、设备描述和厂商。程序不会修改或删除这两处注册表。

运行日志首行包含程序版本号和作者信息，便于确认网管系统实际推送的版本。

示例成功结果：

```json
{"exitCode":0,"mode":"apply","changed":true,"failures":0}
```

退出码：

| 退出码 | 含义 |
|---:|---|
| 0 | 执行成功 |
| 1 | 修复或回滚失败 |
| 2 | 参数错误 |
| 3 | 权限不足 |
| 4 | 修复完成但需要稍后重启 |
| 5 | 审计发现不合规项 |

## 验证脚本

在 `dist` 目录运行：

```bat
verify-remediator.bat
```

脚本会检查服务、防火墙规则、远程桌面注册表、NetBIOS 配置、本机端口监听、网络配置记录和 USB 存储设备记录，并将中文结果写入同目录的 `verification-report.html`。报告可直接用 Windows 自带浏览器打开，不需要另外安装程序；每次验证会覆盖上一份报告。报告先提供“预期结果、实际检查结果、结论”的通俗汇总，再逐项列出 10 条防火墙规则、每个 NetBIOS 网卡接口、每条网络配置记录和每个 USB 存储设备记录，最后保留原始检查信息。端口是否真正无法从网络访问，仍应从另一台电脑进行远程连接测试。

## 回滚

修复前会将服务、RDP 和 NetBIOS 等状态保存到系统数据目录。需要恢复时运行：

```bat
remediator.exe /rollback
```

回滚需要 SYSTEM 或已提权的管理员权限，程序不会自动重启计算机。

## 构建

在安装 Visual Studio C++ Build Tools、Windows SDK 和 CMake 的 Windows 构建机上执行：

```bat
cmake -S . -B build -A Win32
cmake --build build --config Release
```

生成的 `remediator.exe` 为 32 位 PE 程序，可运行在 32 位和 64 位 Windows 上；使用 `/MT` 静态运行库，不依赖目标机安装 VC++ 运行库、.NET、PowerShell 或 WMI。

## 注意事项

- 禁用 Server 服务会关闭本机文件和打印共享。
- 防火墙规则只阻断入站，不影响普通客户端出站访问。
- 域策略或其他安全软件可能覆盖本地配置，最终应以复检和远程端口测试为准。
- `rule-signer.exe` 当前仅为后续外置规则扩展预留工具，第一版只使用程序内置规则。

## 许可证

Copyright 2026 倚栏听雨。

本项目采用 **Apache License 2.0 + Commons Clause License Condition v1.0**。
你可以查看、使用、修改和再分发本项目，但不得以 Commons Clause 所定义的
“Sell”方式销售本软件。该组合属于源代码可用（source-available）许可，
不属于 OSI 定义的开源许可证。完整条款请参阅 [LICENSE](LICENSE)。
