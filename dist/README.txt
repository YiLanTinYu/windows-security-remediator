# Windows 高危端口阻断工具使用说明

Security Remediator 用于 Windows 终端高危端口加固和现场安全检查。交付包中有两类程序，它们的作用不同：

| 类型 | 程序 | 主要用途 | 是否修改系统 |
|---|---|---|---|
| 静默修复版 | `remediator.exe`、`remediator-x64.exe` | 阻断端口、关闭共享和远程桌面；静默生成 HTML 报告 | 是 |
| 现场检查版 | `remediator-inspector.exe`、`remediator-inspector-x64.exe` | 显示检查进度并生成 HTML 报告 | 否 |

- 当前版本：`1.2.4.0`
- 作者：倚栏听雨
- 支持目标：Windows 7 SP1、Windows 10、Windows 11
- 架构：x86（32 位）和 x64（64 位）
- 修复核心：原生静态 EXE，不需要额外安装 VC++ 运行库；生成 HTML 报告时调用 Windows 自带 PowerShell
- 现场检查：使用 Windows 自带 PowerShell 生成离线 HTML 报告

> 最重要的区别：两种版本生成相同结构的 HTML 报告。现场检查版显示进度并自动打开报告；静默修复版不显示界面，也不打开报告。两种版本都不会删除浏览器密码。

## 一、建议操作顺序

推荐顺序：`现场检查 → 判断结果 → 静默修复 → 再次现场检查 → 外部端口验证`。

现场处理一台电脑时，建议严格按以下顺序操作。

### 第一步：运行现场检查版

在待检查用户本人登录的 Windows 桌面中，以管理员权限运行：

```text
64 位系统：remediator-inspector-x64.exe
32 位系统：remediator-inspector.exe
```

现场检查版会：

1. 显示检查进度。
2. 检查端口阻断规则、Server 服务、远程桌面、NetBIOS 等状态。
3. 读取网络配置和 USB 存储设备注册表记录。
4. 检查 Edge、Chrome、Firefox、Internet Explorer 是否存在保存密码。
5. 生成并自动打开 HTML 报告。

### 第二步：阅读检查结果

重点查看报告首页的汇总：

- `通过`：本机检查结果符合预期。
- `异常`：发现未达到预期的项目。
- `需复核`：无法只依靠本机信息作出最终判断。
- `已识别`：已经识别到浏览器安装，仅作状态记录。
- `不适用`：未安装该浏览器。

### 第三步：需要时运行静默修复版

如果报告中的端口、服务、防火墙、远程桌面或 NetBIOS 项目异常，可以在管理员命令提示符或管理员 PowerShell 中运行：

```text
64 位系统：remediator-x64.exe /apply
32 位系统：remediator.exe /apply
```

无参数运行与 `/apply` 作用相同：

```text
remediator-x64.exe
remediator-x64.exe /apply
```

静默修复程序没有窗口，也不会弹出“修复成功”对话框。它会等待 HTML 报告生成后再退出，但不会自动打开报告。命令结束或网管任务返回退出码，表示修复和报告生成过程已经运行完毕。

### 第四步：再次运行现场检查版

修复完成后，重新运行对应架构的现场检查版，生成新的报告并确认系统加固项已经通过。

### 第五步：从另一台电脑测试端口

本机报告通过，不等于外部连接一定被阻断。最终还应从同一网络中的另一台电脑测试目标终端端口。

> 如果现场人员正在使用远程桌面、SSH 或文件共享连接目标电脑，执行修复可能立即断开当前连接。应先确认现场操作方式和后续管理通道。

## 二、交付文件说明

干净的 `dist` 交付目录包含以下 10 个文件：

| 文件 | 用途 |
|---|---|
| `remediator.exe` | x86 静默修复版 |
| `remediator-x64.exe` | x64 静默修复版 |
| `remediator-inspector.exe` | x86 现场检查版 |
| `remediator-inspector-x64.exe` | x64 现场检查版 |
| `verify-remediator.bat` | 新手使用的基础验证入口 |
| `verify-remediator.ps1` | 静默版、现场检查版和基础验证共用的报告脚本 |
| `README.txt` | 本使用说明的文本版本 |
| `LICENSE` | 软件许可条款 |
| `app-icon.png` | PNG 格式程序图标 |
| `remediator.ico` | ICO 格式程序图标 |

运行后生成的日志、JSON、文本结果和 HTML 报告不是初始交付文件，不需要提前复制到其他电脑。

`rule-signer.exe` 是开发预留工具，不需要部署到终端。

## 三、如何选择 32 位或 64 位程序

| 操作系统 | 静默修复版 | 现场检查版 |
|---|---|---|
| Windows 7/10 32 位 | `remediator.exe` | `remediator-inspector.exe` |
| Windows 7/10/11 64 位 | 优先 `remediator-x64.exe` | 优先 `remediator-inspector-x64.exe` |

x86 程序可以在 64 位 Windows 上运行，但交付包已经提供原生 x64 版本，因此 64 位系统优先使用带 `-x64` 的文件。

不要在 32 位 Windows 上运行 x64 程序。

查看系统类型的方法：

1. 右键“此电脑”或“计算机”。
2. 打开“属性”。
3. 查看“系统类型”。

## 四、现场检查版详细用法

### 4.1 运行条件

现场检查版应满足以下条件：

- 现场检查 EXE 与 `verify-remediator.ps1` 必须放在同一文件夹。
- 应在待检查用户本人登录的桌面运行。
- 双击程序后会申请管理员权限，请在 UAC 窗口中确认。
- 不建议使用 SYSTEM 或另一个管理员账户检查浏览器密码，因为它们对应不同的用户配置目录。

### 4.2 运行方法

64 位系统双击：

```text
remediator-inspector-x64.exe
```

32 位系统双击：

```text
remediator-inspector.exe
```

也可以从管理员命令提示符运行：

```bat
cd /d "C:\SecurityRemediator"
remediator-inspector-x64.exe
```

从 PowerShell 运行时必须添加当前目录前缀：

```powershell
cd "C:\SecurityRemediator"
.\remediator-inspector-x64.exe
```

### 4.3 检查内容

现场检查版只读取以下信息：

- Server 文件共享服务状态和启动类型。
- 远程桌面服务和远程桌面连接策略。
- 本程序管理的 10 条防火墙阻断规则。
- 每个网卡的 NetBIOS over TCP/IP 配置。
- 本机相关端口监听信息。
- `NetworkList\Profiles` 中的网络连接记录。
- `USBSTOR` 中的 USB 存储设备记录。
- 浏览器安装状态及当前用户是否存在保存密码。

现场检查版不会修改端口、服务、防火墙、注册表或浏览器配置。

### 4.4 浏览器密码检查

检查结果规则：

| 实际情况 | 报告结论 |
|---|---|
| 浏览器没有保存密码 | 通过 |
| 浏览器存在一条或多条保存密码 | 异常 |
| 浏览器未安装 | 不适用 |
| 密码库被占用、无法读取或格式不支持 | 需复核 |

具体检查范围：

- Edge、Chrome：统计当前用户各浏览器配置文件中的有效密码记录数量。
- Firefox：统计当前用户各配置文件中的密码记录数量。
- Internet Explorer：检查当前用户 IE/WinInet 密码记录索引。

程序只统计记录数量，不选择、解密、显示或导出密码、账号、网站、Cookie 和登录内容。

如果报告发现浏览器保存密码，需要用户进入浏览器的密码管理页面自行确认和删除。静默修复版不会自动删除浏览器密码。

### 4.5 HTML 报告名称

报告首页显示：

```text
被检查终端IP地址:192.168.1.20  MAC地址：AA-BB-CC-DD-EE-FF
```

文件名使用相同的 IP 和 MAC：

```text
verification-report_192.168.1.20_AA-BB-CC-DD-EE-FF.html
```

程序优先选择已连接且具有 IPv4 默认网关的主用网卡。每次检查会删除同目录旧的 `verification-report*.html`，只保留最新一份报告。

报告是离线 HTML 文件，可直接使用 Windows 自带浏览器打开，不需要安装其他阅读软件。

### 4.6 可选参数

```bat
remediator-inspector-x64.exe /no-open
remediator-inspector-x64.exe /no-pause
```

- `/no-open`：完成后不自动打开 HTML 报告。
- `/no-pause`：完成后不等待按 Enter，适合脚本调用。

## 五、静默修复版详细用法

### 5.1 运行条件

执行修复、审计或回滚时，必须使用以下任一权限：

- 网管代理的 SYSTEM 身份；或
- 已经提升权限的 Administrators 组成员。

仅仅属于 Administrators 组不等于当前程序已经提升。人工运行时，应先右键“命令提示符”或“Windows PowerShell”，选择“以管理员身份运行”。

静默版 EXE、`verify-remediator.ps1` 和同架构的现场检查 EXE 应放在同一文件夹。现场检查 EXE 在这里提供浏览器密码条目计数能力，静默版不会打开它的窗口。

### 5.2 修复内容

静默修复版会执行以下系统加固：

1. 启用 Windows 防火墙的域、专用和公用配置文件。
2. 创建或修正指定高危端口的入站阻断规则。
3. 停止并禁用 `LanmanServer`（Server）服务。
4. 在所有网卡上禁用 NetBIOS over TCP/IP。
5. 设置系统拒绝远程桌面连接。
6. 停止并禁用 `TermService`。
7. 保存修复前的服务、远程桌面和 NetBIOS 状态，供回滚使用。

静默修复版不会：

- 停止 Windows RPC 核心服务 `RpcSs`。
- 删除电脑中已经定义的共享名称。
- 阻断客户端访问外部网页或文件服务器的出站连接。
- 删除浏览器中保存的密码。
- 自动重启电脑。
- 绕过域策略、终端安全软件或其他安全控制。

### 5.3 执行修复

管理员命令提示符：

```bat
cd /d "C:\SecurityRemediator"
remediator-x64.exe /apply
echo 退出码：%ERRORLEVEL%
```

管理员 PowerShell：

```powershell
cd "C:\SecurityRemediator"
.\remediator-x64.exe /apply
$LASTEXITCODE
```

32 位系统将文件名替换为 `remediator.exe`。

### 5.4 只审计、不修改

```bat
remediator-x64.exe /audit
```

`/audit` 不执行修复，程序退出前会在 EXE 同目录生成完整 HTML 报告，但不会自动打开。

### 5.5 回滚

```bat
remediator-x64.exe /rollback
```

回滚会删除本程序管理的防火墙规则，并根据备份尝试恢复 Server 服务、远程桌面服务、远程桌面连接策略和 NetBIOS 配置。

备份位置：

```text
%ProgramData%\SecurityRemediator\backup.state
```

首次 `/apply` 创建初始备份。以后重复 `/apply` 会保留有效初始备份，不会用已经加固后的状态覆盖它。回滚后必须重新检查系统功能和安全状态。

### 5.6 指定结果目录

```bat
remediator-x64.exe /apply /log-dir "D:\SecurityLogs"
remediator-x64.exe /audit /log-dir "D:\SecurityLogs"
```

指定目录的上级目录应存在，并允许当前账户写入。

### 5.7 重复运行

程序支持重复运行：

- 已正确存在的规则不会重复创建。
- 缺失规则会被补充。
- 错误规则会被修正。
- 同名重复规则会被清理并恢复为一条标准规则。
- 程序只处理自己的精确规则名，不删除其他软件或管理员创建的规则。
- 有效初始备份不会被覆盖。

## 六、两种版本的关系

| 问题 | 静默修复版 | 现场检查版 |
|---|---|---|
| 是否显示界面和进度 | 否 | 是 |
| 是否修改系统 | 是，`/apply` 模式 | 否 |
| 是否适合网管批量推送 | 是 | 不建议用于无人值守浏览器检查 |
| 是否检查浏览器保存密码 | 以普通管理员运行时检查该用户；SYSTEM 下标记“需复核” | 是，检查当前登录用户 |
| 是否删除浏览器密码 | 否 | 否 |
| 是否生成 HTML 报告 | 会，只保存不打开 | 会，并自动打开 |
| 是否可现场运行 | 可以，但仍保持静默 | 可以，推荐先运行 |

现场检查发现系统加固项异常后，可以在现场运行静默修复版。静默版完成后已经生成同结构的新报告；如需在屏幕上查看检查进度或复核当前用户的浏览器密码，再运行现场检查版。

## 七、端口阻断范围

程序在 Windows 防火墙的域、专用、公用配置文件中管理以下入站阻断规则：

| 协议 | 端口 | 常见用途 |
|---|---:|---|
| TCP | 22 | SSH |
| TCP | 135 | RPC Endpoint Mapper |
| TCP | 136 | 加固范围 |
| UDP | 136 | 加固范围 |
| UDP | 137 | NetBIOS 名称服务 |
| UDP | 138 | NetBIOS 数据报服务 |
| TCP | 139 | NetBIOS 会话服务 |
| TCP | 445 | SMB 文件共享 |
| TCP | 3389 | 远程桌面 |
| UDP | 3389 | 远程桌面 |

规则名称使用 `SecurityRemediator - Block` 前缀。

## 八、如何判断静默程序已经运行完毕

### 人工运行

在命令提示符或 PowerShell 中启动程序。命令提示符重新出现后，程序已经退出。随后查看退出码和结果文件。

### 网管系统运行

网管代理应：

1. 完整复制程序到目标电脑本地目录。
2. 以 SYSTEM 或已提升管理员权限启动 `/apply`。
3. 等待 EXE 进程退出。
4. 读取进程退出码。
5. 收集 `last-result.json`、`result.txt`、`remediator.log` 和 `verification-report_<IP>_<MAC>.html`。

不要通过“是否弹出窗口”判断完成状态，因为静默版不会显示窗口。

## 九、结果文件与退出码

静默修复版默认在 EXE 同目录覆盖生成：

| 文件 | 用途 |
|---|---|
| `remediator.log` | 最近一次运行过程和失败项 |
| `last-result.json` | 网管系统读取的结构化结果 |
| `result.txt` | 面向人工阅读的简要中文结果 |
| `verification-report_<IP>_<MAC>.html` | 与现场版相同结构的完整报告，只保存、不自动打开 |

现场检查版同样在同目录生成：

```text
verification-report_<IP>_<MAC>.html
```

退出码：

| 退出码 | 含义 | 建议处理 |
|---:|---|---|
| 0 | 执行成功，或审计符合要求 | 继续复检 |
| 1 | 修复失败或回滚不完整 | 查看日志失败项 |
| 2 | 参数错误 | 检查命令和引号 |
| 3 | 权限不足 | 使用 SYSTEM 或提升的管理员权限 |
| 4 | 修复完成但建议稍后重启 | 安排维护窗口重启后复检 |
| 5 | 审计或检查发现不合规项 | 根据报告处理后复检 |

网管系统可把静默修复版退出码 `0` 和 `4` 作为修复成功，但仍应安排复检。

## 十、基础验证脚本

双击：

```text
verify-remediator.bat
```

该脚本只读取系统状态并生成 HTML 报告，不执行修复。它适合验证端口、服务、防火墙、NetBIOS、网络和 USB 记录。

直接双击基础验证脚本时不启用浏览器保存密码检查。静默版和现场检查版会启用该部分；但网管代理以 SYSTEM 运行静默版时，报告会把登录用户的浏览器密码项目标记为“需复核”，避免把 SYSTEM 配置文件误当作当前用户。需要准确检查时，应由待检查用户本人运行现场检查版。

## 十一、从另一台电脑验证端口

在另一台 Windows 电脑的 PowerShell 中运行：

```powershell
Test-NetConnection 192.168.1.100 -Port 22
Test-NetConnection 192.168.1.100 -Port 135
Test-NetConnection 192.168.1.100 -Port 136
Test-NetConnection 192.168.1.100 -Port 139
Test-NetConnection 192.168.1.100 -Port 445
Test-NetConnection 192.168.1.100 -Port 3389
```

将 `192.168.1.100` 替换为报告首页显示的被检查终端 IP。结果：

```text
TcpTestSucceeded : False
```

表示该 TCP 端口无法建立连接。测试前应确认两台电脑基础网络互通，否则网络故障或路由隔离也会产生 `False`。

Windows 自带 `Test-NetConnection` 不能准确验证 UDP 136、137、138、3389。UDP 应使用单位批准的扫描工具，并结合目标终端日志判断。

## 十二、常见问题

### 12.1 双击静默修复程序没有任何显示

这是正常现象。请在管理员命令行运行并查看退出码，或者查看同目录结果文件。

### 12.2 PowerShell 提示找不到程序

PowerShell 默认不从当前目录搜索 EXE，应使用：

```powershell
.\remediator-x64.exe /apply
```

### 12.3 返回退出码 3

当前进程没有提升权限。请使用 SYSTEM，或从“以管理员身份运行”的命令提示符、PowerShell 启动。

### 12.4 浏览器检查显示“需复核”

可能原因包括浏览器正在占用密码库、文件无法读取、当前运行账户不是待检查用户或密码库格式不受支持。先关闭浏览器，再用待检查用户本人的提升管理员会话重新运行现场检查版。

### 12.5 报告显示端口存在监听记录

本机监听不等于外部能够连接。防火墙可以阻断入站连接，但服务仍可能在本机监听。最终应从另一台电脑测试。

### 12.6 修复后仍显示异常

可能是域组策略、安全软件或终端管理策略覆盖了本地设置。应检查策略来源，不要让程序反复争抢单位统一策略。

### 12.7 多次运行是否产生重复规则

不会。程序会按精确规则名检查、修正和清理重复项。

## 十三、重要风险和使用边界

- 执行修复前必须确认目标电脑不需要提供文件共享、打印共享、SSH 或远程桌面服务。
- 禁用 `LanmanServer` 会关闭本机文件共享和打印共享服务端能力。
- 禁用 `TermService` 并阻断 3389 会关闭远程桌面。
- 阻断 TCP 22 会关闭通过 SSH 进入本机的能力。
- 网管代理后续管理通道不能依赖 22、135、139、445 或 3389。
- 当前端口阻断使用 Windows 防火墙规则，不是 IP 安全策略或域组策略。
- 当前版本没有正式启用外置 `/rules`、`/signature` 和规则签名功能。
- 本工具不是完整的漏洞扫描器。
- Windows 7 已停止官方支持，必须在隔离测试环境进行兼容性验收。
- Win7 SP1 x86/x64、Win10 x86/x64、Win11 x64 和真实网管代理环境仍需分别验收。
- 网络配置、USB 设备和浏览器检查结果属于终端使用信息，不应公开上传。

## 十四、版权与许可证

Copyright 2026 倚栏听雨。保留所有权利。

本项目采用 **Apache License 2.0 + Commons Clause License Condition v1.0**。该组合属于源代码可用（source-available）许可，不属于 OSI 定义的开源许可证。完整条款见 `LICENSE`。

`third_party/sqlite` 中的 SQLite 源码属于公有领域，不受本项目 Commons Clause 限制；来源、版本和校验值见该目录的 `README.md`。
