# 高危端口阻断项目交接说明

## 1. 项目概况

- 项目名称：高危端口阻断工具（Security Remediator）
- 当前版本：1.2.4.0
- 作者：倚栏听雨
- 项目目录：`C:\运维小工具\高危端口阻断`
- 交付目录：`C:\运维小工具\高危端口阻断\dist`
- 支持系统：Windows 7 SP1、Windows 10、Windows 11
- 程序架构：同时交付原生 Win32 x86 和 x64；x86 用于 32 位系统并兼容 64 位系统，x64 用于 64 位系统
- 运行方式：原生静态 EXE 后台静默运行，不依赖 .NET 或额外 VC++ 运行库；HTML 报告使用 Windows 自带 PowerShell 和同目录验证脚本生成

## 2. 已确认需求

1. 默认执行检测和修复，不自动重启，重复执行保持幂等。
2. 支持网管系统使用 SYSTEM 或已提权的 Administrators 组成员权限静默推送。
3. 阻断以下入站端口：
   - TCP：22、135、136、139、445、3389
   - UDP：136、137、138、3389
4. 停止并禁用 `LanmanServer`（Server）服务，关闭文件和打印共享服务端能力。
5. 在所有网卡上禁用 NetBIOS over TCP/IP。
6. 拒绝远程桌面连接，停止并禁用 `TermService`。
7. 不停止 RPC 核心服务 `RpcSs`。
8. 保留客户端访问网页和外部文件服务器等出站能力。
9. 支持只检测、修复、回滚和自定义日志目录。
10. 日志默认保存在程序同目录，仅保留一份运行结果和一份验证结果。
11. 提供中文结果，便于非专业人员判断是否成功。
12. 程序带有自定义图标、版本信息和作者信息。
13. 验证脚本只读采集网络配置与 USB 存储设备注册表记录，并直接写入离线 `verification-report_<IP>_<MAC>.html`。
14. 首次 `/apply` 创建初始回滚备份；后续重复运行校验并保留有效备份，仅在备份缺失或格式无效时重新创建。
15. 提供非静默现场检查版，显示进度并自动打开 HTML；分别列出 Edge、Chrome、Firefox、IE 的安装状态，并判断已安装浏览器是否存在保存密码，只统计数量，不读取或解密密码内容。
16. 报告首页显示被检查终端主用网卡的 IPv4 和 MAC，文件名同时包含相同的 IP/MAC；每次检查只保留一份最新报告。
17. 静默版在修复、审计或回滚结束后自动生成与现场版相同结构的 HTML 报告，保存到 EXE 同目录但不自动打开；SYSTEM 身份下登录用户浏览器密码项目必须标为“需复核”。

## 3. 现有功能

### 3.1 系统加固

- 启用 Windows 防火墙的域、专用、公用配置文件。
- 创建 `SecurityRemediator` 命名的入站阻断规则。
- 防火墙规则按精确名称保持幂等：缺失则创建、单条错误则修正、多条重复则清理后重建一条。
- 停止并禁用 `LanmanServer`。
- 停止并禁用 `TermService`。
- 设置 `fDenyTSConnections=1`，拒绝远程桌面连接。
- 设置网卡 `NetbiosOptions=2`，禁用 NetBIOS over TCP/IP。
- 修改前保存服务、RDP 和 NetBIOS 等状态。
- `/rollback` 只恢复本程序记录和修改的项目。

### 3.2 命令行

```bat
remediator.exe
remediator.exe /apply
remediator.exe /audit
remediator.exe /rollback
remediator.exe /apply /log-dir "D:\SecurityLogs"
```

- 无参数与 `/apply`：检测并修复。
- `/audit`：只检测，不修改。
- `/rollback`：从最近一次有效备份恢复。
- `/log-dir`：覆盖默认日志目录。

### 3.3 输出文件

默认写入 `remediator.exe` 所在目录：

```text
remediator.log       最近一次程序运行日志
last-result.json     最近一次机器可读结果
result.txt           最近一次中文摘要
verification-report_<IP>_<MAC>.html  最近一次离线 HTML 验证报告
```

每次运行会覆盖相应的旧日志，避免长期积累大量文件。

### 3.4 退出码

| 退出码 | 含义 |
|---:|---|
| 0 | 全部符合或修复成功 |
| 1 | 至少一项修复失败，或回滚不完整 |
| 2 | 参数或规则格式错误 |
| 3 | 权限不足 |
| 4 | 修复成功，但建议稍后重启 |
| 5 | 审计发现不合规项 |

网管平台可把退出码 `0` 和 `4` 视为修复成功，并采集同目录的 `last-result.json`。

## 4. 交付文件

`dist` 目录应保留：

```text
remediator.exe
remediator-x64.exe
remediator-inspector.exe
remediator-inspector-x64.exe
verify-remediator.bat
verify-remediator.ps1
README.txt
LICENSE
app-icon.png
remediator.ico
```

- `remediator.exe`：x86 正式修复程序，适用于 32 位系统并兼容 64 位系统。
- `remediator-x64.exe`：x64 正式修复程序，64 位 Win10/Win11 优先使用。
- `remediator-inspector.exe`：x86 非静默现场检查程序，只读检查并显示进度。
- `remediator-inspector-x64.exe`：x64 非静默现场检查程序，只读检查并显示进度。
- `verify-remediator.bat`：适合新手使用的验证入口。
- `verify-remediator.ps1`：验证逻辑，由批处理调用。
- `README.txt`：终端用户使用说明。
- `LICENSE`：Apache-2.0 + Commons Clause v1.0 完整许可条款。
- `app-icon.png`、`remediator.ico`：程序图标源文件。

`rule-signer.exe` 当前属于开发占位工具，不应推送到终端。

## 5. 构建方法

### 5.1 构建环境

- Visual Studio / MSVC
- Windows SDK
- CMake

构建目标使用 `/MT` 静态运行库。为避免中文路径影响链接器和 PDB，建议分别使用纯英文构建目录：

```bat
cmake -S "C:\运维小工具\高危端口阻断" -B "C:\Build\SecurityRemediator-x86" -A Win32
cmake --build "C:\Build\SecurityRemediator-x86" --config Release

cmake -S "C:\运维小工具\高危端口阻断" -B "C:\Build\SecurityRemediator-x64" -A x64
cmake --build "C:\Build\SecurityRemediator-x64" --config Release
```

构建完成后，应把正式 EXE 更新到 `dist`，并检查文件属性中的版本、说明、作者和图标。

## 6. 测试情况

### 6.1 已完成的本机检查

- 程序可以在管理员 PowerShell 中静默执行。
- 日志能够写入程序同目录。
- `LanmanServer` 已验证为 `STOPPED` 和 `DISABLED`。
- `net share` 无法启动 Server 服务，返回系统错误 1058，符合禁用预期。
- 已提供一键验证脚本，检查服务、RDP、NetBIOS、防火墙规则和本机监听状态。
- 验证脚本生成单个离线 HTML 报告，汇总全部检查项，对比预期结果和实际结果，并逐项列出防火墙规则、NetBIOS 网卡、网络配置和 USB 存储设备记录。
- 程序已加入图标、版本 1.2.4.0 和作者“倚栏听雨”。
- 1.2.3.0 使用静态 SQLite 对 Edge/Chrome 密码库执行只读计数，不需要安装数据库组件；Firefox 和 IE 只检查密码记录是否存在。
- 1.2.3.0 报告首页及文件名包含主用活动网卡的 IPv4/MAC，每次检查只保留一份最新报告。
- 1.2.3.0 Release/Win32 x86 与 x64 构建通过；IP/MAC 文件名、首页信息一致性及两个现场检查 EXE 端到端测试通过。
- 验证脚本将网络配置与 USBSTOR 中文列表写入带 IP/MAC 文件名的 HTML 报告。
- x86/x64 现场检查程序端到端测试通过，均能等待检查完成并生成包含浏览器已保存密码检查的 HTML 报告。
- 1.2.4.0 静默版会隐藏启动报告脚本、等待相同结构的 HTML 报告写完后退出，并且不调用浏览器打开报告。
- 浏览器检查会访问当前用户密码存储，但只统计记录数量，不选择、解密、显示或导出账号、网站、密码及 Cookie。
- 浏览器安装状态与保存密码结果分开显示：无保存密码为“通过”，存在保存密码为“异常”，未安装为“不适用”，无法读取为“需复核”。
- 非提升令牌读取 `NetworkList\Profiles` 可能返回拒绝访问；正式环境应使用 SYSTEM 或已提权管理员运行验证脚本。

### 6.2 正式部署前仍需完成

- 在 Windows 7 SP1 x86/x64、Windows 10 x86/x64、Windows 11 x64 分别测试。
- 使用网管代理的真实执行账户测试无界面静默推送。
- 从另一台电脑对目标机进行 TCP 端口探测。
- 使用支持 UDP 的扫描工具验证 UDP 136、137、138、3389。
- 验证普通网页访问及客户端访问外部文件服务器不受影响。
- 验证 `/audit` 不修改系统。
- 验证重复 `/apply` 的幂等性。
- 验证 `/rollback` 能恢复修改前状态。
- 验证域策略或第三方安全软件覆盖设置时，日志能够准确报告失败。

运行本机验证：

```bat
verify-remediator.bat
```

注意：本机仍显示某端口处于监听状态，不代表防火墙阻断失败。入站阻断必须从另一台电脑测试。

## 7. 网管推送建议

- 执行账户：SYSTEM，或已提权的本地 Administrators 组成员。
- 执行命令：`remediator.exe /apply`
- 窗口方式：隐藏窗口。
- 任务设置：等待程序退出并读取退出码。
- 成功判定：退出码为 `0` 或 `4`。
- 结果采集：读取 EXE 同目录的 `last-result.json` 和 `result.txt`。
- 必须先完整复制文件到本机，再启动程序。

程序会阻断 TCP 22 和 TCP 3389。部署前必须确认网管代理不依赖 SSH 或远程桌面维持任务。

## 8. 回滚与备份

修复前的状态保存在：

```text
%ProgramData%\SecurityRemediator\backup.state
```

执行：

```bat
remediator.exe /rollback
```

会尝试：

- 删除本程序创建的防火墙规则。
- 恢复 Server 和远程桌面服务的启动类型与运行状态。
- 恢复 RDP 注册表原值。
- 恢复各网卡的 NetBIOS 原值。

程序不会自动重启计算机。备份损坏、缺失或部分恢复失败时，应以退出码和日志为准。

## 9. 注意事项与现有限制

1. 当前端口阻断实际使用 Windows 防火墙规则，尚未迁移到 IP 安全策略或域组策略。
2. 外置 `/rules`、`/signature` 和 RSA/SHA-256 签名规则机制尚未正式启用。
3. 禁用 `LanmanServer` 会关闭本机文件共享和打印共享服务端能力。
4. 禁用 `TermService` 会关闭远程桌面。
5. 阻断 TCP 22 会影响本机 SSH 服务。
6. 域策略或第三方安全软件可能覆盖本地防火墙设置。
7. Windows 7 已停止官方支持，兼容性必须在隔离测试环境确认。
8. 正式批量部署前必须先做虚拟机测试和小范围灰度。
9. 不要把开发目录、临时构建文件、测试日志或签名私钥放入交付目录。
10. 每次发布应记录 EXE 的版本号、SHA-256 哈希值和测试结论。

## 10. 后续工作建议

- 完成全系统矩阵测试和真实网管平台灰度测试。
- 确认是否继续采用 Windows 防火墙，或增加 IP 安全策略/组策略模式。
- 正式实现并验证外置签名规则机制。
- 对回滚、域策略覆盖、损坏备份和部分失败场景做自动化测试。
- 为每个正式版本保存源码标签、构建环境、EXE 哈希和验收记录。
