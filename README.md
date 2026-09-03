# Windows 高危端口静默修复工具

Security Remediator 是一款面向 Windows 终端的静默安全加固工具。程序用于阻断指定高危入站端口，关闭本机文件共享和远程桌面服务，并提供审计、回滚和离线验证功能。

- 当前版本：`1.2.1.0`
- 作者：倚栏听雨
- 运行方式：静默、无窗口、无交互、不会自动重启
- 程序类型：同时提供原生 x86（32 位）和 x64（64 位）EXE
- 目标系统：Windows 7 SP1、Windows 10、Windows 11

> 使用前请确认目标电脑不需要提供文件共享、打印共享、SSH 或远程桌面服务。建议先在测试电脑验证，再通过网管系统批量推送。

## 一、程序会修改什么

### 1. 阻断高危入站端口

程序在 Windows 防火墙的域、专用、公用配置文件中创建入站阻断规则：

| 协议 | 端口 | 常见用途 |
|---|---:|---|
| TCP | 22 | SSH 远程连接 |
| TCP | 135 | RPC Endpoint Mapper |
| TCP | 136 | 高危端口加固范围 |
| UDP | 136 | 高危端口加固范围 |
| UDP | 137 | NetBIOS 名称服务 |
| UDP | 138 | NetBIOS 数据报服务 |
| TCP | 139 | NetBIOS 会话服务 |
| TCP | 445 | SMB 文件共享 |
| TCP | 3389 | Windows 远程桌面 |
| UDP | 3389 | Windows 远程桌面 |

每条规则都使用 `SecurityRemediator - Block` 前缀。重复运行时：

- 正确规则只保留一条，不重复创建。
- 缺失规则会被补充。
- 配置错误的同名规则会被修正。
- 同名重复规则会被清理并重建为一条标准规则。
- 程序只处理自己的精确规则名，不删除其他软件或管理员创建的规则。

### 2. 关闭文件共享

- 停止并禁用 `LanmanServer`（Server）服务。
- 在所有网卡上禁用 NetBIOS over TCP/IP。
- 不删除电脑中已经定义的共享名称。
- 不阻断客户端访问其他电脑或服务器的出站连接。

### 3. 关闭远程桌面

- 设置 `fDenyTSConnections=1`，拒绝远程桌面连接。
- 停止并禁用 `TermService`（Remote Desktop Services）服务。
- 同时阻断 TCP 和 UDP 3389 入站连接。

### 4. 不会执行的操作

- 不停止 `RpcSs` 等 Windows RPC 核心服务。
- 不主动访问互联网或内网接口。
- 不自动重启电脑。
- 不修改网络配置和 USB 设备注册表记录；验证脚本只读取这些信息。

## 二、运行条件

执行修复、审计或回滚时，必须满足以下任一条件：

- 网管代理以 `SYSTEM` 身份运行；或
- 使用已经提升权限的 Administrators 组成员运行。

仅仅属于 Administrators 组并不代表当前进程已经提升权限。人工测试时，应右键“命令提示符”或“Windows PowerShell”，选择“以管理员身份运行”。

程序不依赖 VC++ 运行库、.NET、WMI 或 PowerShell。验证脚本需要使用 Windows 自带的 PowerShell。

## 三、需要复制哪些文件

### 只执行修复或审计

根据目标系统选择一个 EXE：

```text
remediator.exe       x86 版本：用于 32 位 Windows，也兼容 64 位 Windows
remediator-x64.exe   x64 版本：用于 64 位 Windows
```

Win10、Win11 64 位系统优先使用 `remediator-x64.exe`；Win7 32 位系统必须使用 `remediator.exe`。不要在 32 位系统上运行 x64 版本。

### 执行修复并生成完整验证报告

选择一个对应架构的 EXE，并与两个验证脚本放在同一个文件夹：

```text
remediator.exe 或 remediator-x64.exe
verify-remediator.bat
verify-remediator.ps1
```

可选交付文件：

```text
README.txt
LICENSE
```

`verification-report.html`、`remediator.log`、`last-result.json` 和 `result.txt` 都是运行后生成的结果文件，不需要预先复制到其他电脑。

### 使用非静默现场检查版

根据系统架构选择一个现场检查 EXE，并与验证脚本放在同一个文件夹：

```text
remediator-inspector.exe       x86 现场检查版
remediator-inspector-x64.exe   x64 现场检查版
verify-remediator.ps1          两个版本共用的检查脚本
```

现场检查版只读取系统和浏览器设置，不执行端口修复，也不修改浏览器配置。

## 四、本机人工运行方法

下面的示例使用 x86 文件名 `remediator.exe`。如果目标电脑是 Win10 或 Win11 64 位，可以把命令中的文件名替换为 `remediator-x64.exe`，其他参数和操作完全相同。

### 第一步：打开管理员命令提示符

进入程序所在目录，例如：

```bat
cd /d "C:\SecurityRemediator"
```

PowerShell 必须使用当前目录前缀：

```powershell
cd "C:\SecurityRemediator"
.\remediator.exe
```

### 第二步：执行修复

下面两条命令作用相同：

```bat
remediator.exe
remediator.exe /apply
```

程序静默运行，不弹出窗口，也不会在屏幕上显示成功提示。命令返回后，请查看同目录的 `result.txt`、`last-result.json` 和 `remediator.log`。

### 第三步：生成验证报告

双击或在命令行运行：

```bat
verify-remediator.bat
```

验证完成后，同目录会生成：

```text
verification-report.html
```

双击该文件即可用 Windows 自带浏览器查看，不需要安装其他程序。

### 第四步：使用非静默现场检查版

在 64 位 Win10/Win11 上双击：

```text
remediator-inspector-x64.exe
```

32 位系统使用：

```text
remediator-inspector.exe
```

程序会请求管理员权限，显示检查进度，等待全部检查结束，然后自动打开 `verification-report.html`。控制台窗口会显示最终结论；从资源管理器双击运行时，按 Enter 键才会关闭窗口。

浏览器检查范围：

- 先分别检查 Microsoft Edge、Google Chrome、Mozilla Firefox、Internet Explorer 是否安装。
- 已安装的 Edge：检查 `PasswordManagerEnabled` 强制策略和当前用户各浏览器配置文件。
- 已安装的 Chrome：检查 `PasswordManagerEnabled` 强制策略和当前用户各浏览器配置文件。
- 已安装的 Firefox：检查 `OfferToSaveLogins` 强制策略和 `signon.rememberSignons` 用户设置。
- 已安装的 Internet Explorer：检查当前用户的 `FormSuggest Passwords` 设置。

该功能只判断“是否允许保存密码”，不会读取、解密、显示或导出已保存密码、账号、Cookie 和登录内容。

报告将“安装状态”和“自动保存密码设置”分成不同检查项。未安装的浏览器显示“未安装/不适用”，不会被写成密码设置“通过”；已安装但没有找到禁用策略或禁用配置时，按“未禁用/异常”处理。

现场检查应在待检查用户本人登录的桌面中运行，并以该用户的提升管理员权限启动。如果使用 SYSTEM 或输入另一个管理员账户的凭据，读取到的浏览器用户配置可能不属于待检查用户，报告会提示人工复核。

命令行可选参数：

```bat
remediator-inspector-x64.exe /no-open    rem 完成后不自动打开报告
remediator-inspector-x64.exe /no-pause   rem 完成后不等待按 Enter
```

## 五、网管系统静默推送方法

推荐流程：

1. 将所需文件完整复制到目标电脑的本地目录。
2. 根据操作系统架构选择 EXE：64 位 Win10/Win11 优先使用 `remediator-x64.exe`，32 位系统使用 `remediator.exe`。
3. 使用网管代理的 SYSTEM 身份或已提升管理员权限启动所选 EXE 的 `/apply` 模式。
4. 等待进程退出并读取退出码。
5. 收集 `last-result.json`、`result.txt` 和 `remediator.log`。
6. 如需完整报告，再运行 `verify-remediator.bat` 并收集 `verification-report.html`。

示例命令：

```bat
remediator.exe /apply
set REMEDIATOR_EXIT=%ERRORLEVEL%
```

64 位版本示例：

```bat
remediator-x64.exe /apply
set REMEDIATOR_EXIT=%ERRORLEVEL%
```

网管系统必须等待程序执行结束后再读取结果文件。程序不会自动重启，也不会弹出需要人工点击的窗口。

> 修复会关闭 SMB、SSH 和远程桌面等入站能力。网管代理后续管理通道不能依赖 22、135、139、445 或 3389 端口。

## 六、命令行参数

`remediator.exe` 和 `remediator-x64.exe` 支持完全相同的参数。下表使用 x86 文件名作为示例：

| 命令 | 作用 | 是否修改系统 |
|---|---|---|
| `remediator.exe` | 默认检测并修复 | 是 |
| `remediator.exe /apply` | 检测并修复 | 是 |
| `remediator.exe /audit` | 审计当前状态 | 否 |
| `remediator.exe /rollback` | 按最近一次备份尝试恢复 | 是 |
| `remediator.exe /log-dir "D:\SecurityLogs"` | 将本次结果写入指定目录 | 取决于运行模式 |
| `remediator.exe /audit /log-dir "D:\SecurityLogs"` | 审计并将结果写入指定目录 | 否 |

参数不区分大小写。包含空格的路径必须使用英文双引号。`/log-dir` 指定目录的上级目录应当已经存在，并允许当前账户写入。

当前版本不提供可用的外置规则加载功能。`rule-signer.exe` 是开发预留工具，部署终端时不需要携带。

## 七、结果文件和退出码

默认情况下，以下文件写入所运行 EXE 的所在目录，每次运行覆盖上一份同名结果：

| 文件 | 用途 |
|---|---|
| `remediator.log` | 程序运行过程和失败项 |
| `last-result.json` | 网管系统读取的结构化结果 |
| `result.txt` | 面向人工阅读的简要中文结果 |
| `verification-report.html` | 验证脚本生成的离线详细报告 |

`last-result.json` 示例：

```json
{"exitCode":0,"mode":"apply","changed":true,"failures":0}
```

字段说明：

| 字段 | 含义 |
|---|---|
| `exitCode` | 程序退出码 |
| `mode` | `apply`、`audit` 或 `rollback` |
| `changed` | 本次是否执行了修改操作 |
| `failures` | 检测到的失败项数量 |

退出码说明：

| 退出码 | 含义 | 建议处理 |
|---:|---|---|
| 0 | 执行成功或审计符合要求 | 继续运行验证脚本 |
| 1 | 修复失败或回滚未完成 | 查看日志中的失败项 |
| 2 | 命令行参数错误 | 检查命令拼写和路径引号 |
| 3 | 权限不足 | 改用 SYSTEM 或已提升管理员权限 |
| 4 | 修复完成但建议稍后重启 | 安排维护窗口重启并复检 |
| 5 | 审计发现不合规项 | 执行 `/apply` 后重新审计 |

## 八、如何阅读验证报告

`verify-remediator.bat` 和现场检查版都只读取系统状态，不执行修复。普通验证报告包含：

1. 检查结果汇总：逐项对比预期结果和实际结果。
2. 防火墙规则明细：10 条规则分别显示数量和结论。
3. NetBIOS 网卡明细：每个网卡接口分别显示实际配置值。
4. 网络配置记录：读取 `NetworkList\Profiles` 中的网络名称、GUID、类别和连接时间。
5. USB 存储设备记录：读取 `USBSTOR` 中的设备类型、实例 ID、名称、描述和厂商。
6. 原始检查信息：供管理员进一步排查。

使用 `remediator-inspector.exe` 或 `remediator-inspector-x64.exe` 时，报告还会逐项列出 Edge、Chrome、Firefox 和 Internet Explorer 的安装状态，以及已安装浏览器的密码保存策略或当前用户设置。强制策略优先于用户设置；未安装显示“不适用”，已安装但没有找到禁用配置显示“异常”。

报告结论含义：

| 结论 | 含义 |
|---|---|
| 通过 | 本机检查结果达到预期 |
| 异常 | 本机配置未达到预期或读取失败 |
| 需复核 | 无法仅依靠本机状态作最终判断 |
| 已识别 | 已检测到浏览器安装，仅作状态记录 |
| 不适用 | 未安装该浏览器，无需检查其密码保存设置 |

网络配置和 USB 设备信息可能涉及终端使用记录，请按单位的数据管理要求保存和传输验证报告，不要公开上传报告。

## 九、从另一台电脑测试端口

本机验证通过不等于端口一定无法从网络访问。还应在同一网络中的另一台 Windows 电脑上测试目标电脑 IP。

TCP 测试示例：

```powershell
Test-NetConnection 192.168.1.100 -Port 22
Test-NetConnection 192.168.1.100 -Port 135
Test-NetConnection 192.168.1.100 -Port 136
Test-NetConnection 192.168.1.100 -Port 139
Test-NetConnection 192.168.1.100 -Port 445
Test-NetConnection 192.168.1.100 -Port 3389
```

将 `192.168.1.100` 替换为目标电脑 IP。结果中：

```text
TcpTestSucceeded : False
```

表示该 TCP 端口无法建立连接。测试前应确认两台电脑之间的基础网络是连通的，否则“False”也可能是网络不通、路由隔离或其他防火墙导致。

Windows 自带的 `Test-NetConnection` 不能准确完成 UDP 136、137、138、3389 的验证。UDP 端口应使用单位批准的扫描设备或安全检测工具，并结合目标电脑日志判断。

## 十、回滚方法

执行修复前，程序会把服务、远程桌面和 NetBIOS 等原始状态保存到：

```text
%ProgramData%\SecurityRemediator\backup.state
```

需要恢复时，在已提升的管理员命令提示符或网管系统中运行：

```bat
remediator.exe /rollback
```

回滚会移除本程序管理的防火墙规则，并尝试恢复最近一次备份中的服务、远程桌面和 NetBIOS 状态。回滚完成后必须重新运行验证脚本，并人工确认文件共享、远程桌面和网络功能是否符合预期。

首次执行 `/apply` 时会创建初始备份。以后重复执行 `/apply` 会校验并保留这份有效备份，不再用已经加固后的状态覆盖它；只有备份缺失或格式无效时才重新创建。

## 十一、常见问题

### 1. 双击程序后没有任何显示

这是正常现象。程序设计为后台静默运行，请查看结果文件和退出码。

### 2. PowerShell 提示找不到 EXE

PowerShell 默认不从当前目录查找程序，请使用：

```powershell
.\remediator.exe
```

64 位版本使用：

```powershell
.\remediator-x64.exe
```

### 3. 返回退出码 3

当前进程没有获得足够权限。请使用 SYSTEM 身份或“以管理员身份运行”的终端。

### 4. 验证报告显示端口“需复核”

本机可能仍存在端口监听，但防火墙已经阻断外部访问。必须从另一台电脑测试，不能仅根据 `netstat` 是否显示监听判断失败。

### 5. 重复运行是否会产生重复规则

不会。程序会检查自己的精确规则名，并将每一项保持为一条标准规则。重复运行也不会覆盖已有的有效初始备份。

### 6. 修复后仍被检测为不合规

可能是域组策略、安全软件或终端管理策略覆盖了本地设置。请检查策略来源和验证报告，不要让程序反复争抢单位统一策略。

## 十二、使用边界

- 本工具是针对指定端口和服务的加固工具，不是完整的漏洞扫描器。
- x86 和 x64 是两份独立构建产物，Windows 7 SP1、Windows 10、Windows 11 以及 32/64 位环境仍应分别进行目标机验收。
- 禁用 Server 服务会关闭本机文件共享和打印共享。
- 禁用 TermService 和 3389 会关闭远程桌面。
- 阻断 22 会关闭通过 SSH 进入本机的能力。
- 域策略或安全软件可能覆盖本地设置，最终结果以复检和远程端口测试为准。
- 程序不会绕过域策略、终端安全软件或其他安全控制。

## 版权与许可证

Copyright 2026 倚栏听雨。保留所有权利。

本项目采用 **Apache License 2.0 + Commons Clause License Condition v1.0**。你可以查看、使用、修改和再分发本项目，但不得以 Commons Clause 所定义的“Sell”方式销售本软件。该组合属于源代码可用（source-available）许可，不属于 OSI 定义的开源许可证。完整条款请参阅 [LICENSE](LICENSE)。
