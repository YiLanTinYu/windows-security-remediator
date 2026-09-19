# 终端安全检查与修复工具

版本：2.0.2
作者及版权人：倚栏听雨
许可：Apache License 2.0 + Commons Clause（Source Available，不属于 OSI 标准开源许可）

## 一、工具用途

本套工具用于 Windows 和银河麒麟终端的安全检查、系统配置修复、违规记录清理以及集中报告整理。Windows 正式终端程序采用兼容 Windows 7 SP1 的 32 位静态构建，可在 Windows 7、Windows 10 的 32/64 位系统及 Windows 11 64 位系统运行。银河麒麟 V10 SP1 源码位于 `kylin-security-remediator/`，支持构建 `linux/amd64` 与 `linux/arm64` 单文件程序。

主要工作流程：

```text
修复前检查 → 保存原始结果 → 修复允许处理的系统异常 → 修复后复检 → 生成对比报告
```

现场版和 FTP 版共同使用同一套检查核心、修复核心和合规标准。两者的差异仅是交互方式和是否回传报告。

## 二、交付目录

公开仓库只提供源码和自动化测试，不包含内置 FTP 凭据的部署 EXE、终端报告、日志或本地交付目录。正式交付文件应在受控环境中构建并保存在仓库外部。

```text
01-现场检查修复版
  onsite-check-repair.exe
  README.txt

02-FTP检查修复回传版
  ftp-check-repair.exe
  README.txt

03-违规记录清理版
  record-cleaner.exe
  cleanup-remediator.ps1
  wireless-remediator.ps1
  README.txt

04-报告管理工具
  ftp-report-pruner-x64.exe
  report-issue-exporter-x64.exe
  README.txt
```

除“违规记录清理版”明确列出的脚本外，其余终端程序均为单个 EXE。清理版三个文件必须放在同一目录。

## 三、建议操作顺序

1. 使用现场版或 FTP 版完成修复前检查。
2. 现场版确认结果后输入小写 `yes`；FTP 版会自动执行允许的系统修复。
3. 程序自动复检并生成包含“修复前、修复动作、修复后”的报告。
4. 如果报告发现浏览器保存密码、USB 历史或无线网络历史等违规记录，先保存检查证据，再由当前用户运行记录清理版。
5. 清理完成后，再运行一次现场版的 `/audit-only`，用新检查报告与临时清理报告核对。
6. 在报告服务器目录使用重复报告整理工具，再使用 Excel 汇总工具。

系统修复与违规记录删除分开，是为了避免 SYSTEM 推送误删用户数据，也便于保留整改前证据。

## 四、现场检查修复版

文件：`onsite-check-repair.exe`

右键程序，选择“以管理员身份运行”。程序会先检查并显示通过、异常、需复核数量；输入小写 `yes` 后修复并复检，其他输入不会修改系统。报告生成在程序同目录，默认自动打开 HTML。

常用参数：

```powershell
.\onsite-check-repair.exe /audit-only
.\onsite-check-repair.exe /rollback
.\onsite-check-repair.exe /no-open /no-pause
.\onsite-check-repair.exe /audit-only /no-open /no-pause
```

- `/audit-only`：只检查，不修复。
- `/rollback`：先检查，输入小写 `yes` 后恢复首次修复前备份。
- `/no-open`：不自动打开报告。
- `/no-pause`：结束时不等待按键。

## 五、FTP 静默检查修复回传版

文件：`ftp-check-repair.exe`

适合由网管系统以 SYSTEM 或已提权管理员身份推送。程序无窗口、无确认提示，自动执行修复前检查、系统修复、修复后复检、保存 HTML/JSON 和 FTP 上传。

公开源码默认 FTP 地址为本机占位值 `127.0.0.1:12221`。部署时通过 CMake 缓存参数注入实际地址、用户名和密码；这些信息不得提交到仓库、README、报告或状态文件。普通 FTP 不加密，只应在受控内网中使用。

```powershell
.\ftp-check-repair.exe
.\ftp-check-repair.exe /server=192.0.2.10:12221 /audit-only
.\ftp-check-repair.exe /server=192.0.2.10:12221
.\ftp-check-repair.exe /local-only
.\ftp-check-repair.exe /audit-only /local-only
```

- `/server=地址:端口`：本次运行临时修改 FTP 地址或端口。
- `/server=地址:端口 /audit-only`：使用临时 FTP 地址，只检查、不修复，并上传检查报告。建议先用此方式测试回传。
- 单独使用 `/server=地址:端口`：使用临时 FTP 地址，执行检查、修复、复检并上传报告。确认只检查回传正常后再使用。
- `/local-only`：不上传，但默认仍会执行修复。
- `/audit-only /local-only`：只检查、不修复、不上传。

临时地址只对本次运行有效，不会写入 EXE，也不会改变下次运行使用的默认地址。临时服务器必须使用与当前 EXE 内置配置相同的 FTP 用户名和密码；用户名和密码目前不能通过命令行临时修改。

FTP 上传最多尝试三次。运行结束后查看同目录的 `upload-status.json`：`"uploaded":true` 表示上传成功，`"uploaded":false` 表示上传失败。只检查时如果发现异常，程序退出码可能为 `5`，但报告仍可能已经上传成功，因此应以 `uploaded` 字段判断回传是否成功。上传失败不会删除本地报告，程序同目录会保留 HTML、JSON 和 `upload-status.json`。FTP 服务端必须允许账号写入，并正确开放控制端口及被动模式数据端口。

## 六、自动修复范围

现场版和 FTP 版只修复以下系统配置：

- 默认启用域、专用、公用三个 Windows 防火墙配置文件。若识别到正在运行的 FTP 接收服务，但控制端口、有限被动端口范围、允许来源或规则覆盖不完整，则保留原本关闭的配置文件并标记“需复核”，不开放未知端口。
- 维护 10 条入站阻断规则，各保留一条：TCP 22、135、136、139、445、3389；UDP 136、137、138、3389。
- 停止并禁用 `LanmanServer`（Server 文件共享服务）。
- 停止并禁用 `TermService`（远程桌面服务）。
- 设置 `fDenyTSConnections=1`，拒绝远程桌面连接。
- 将全部可配置网卡的 `NetbiosOptions` 设置为 `2`。

程序不会停止 RPC/RpcSs，不删除原有共享定义，不添加出站阻断，不自动重启，也不会绕过域策略或安全软件。

程序不会停止已识别的 FTP 服务，也不会删除非本程序创建的 FTP 允许规则。报告新增“扫描接收兼容性”及其明细；如果实际依赖 SMB 共享，报告会明确提示其与关闭 Server 服务和 445 端口的安全基线冲突，程序不会自动恢复 SMB。

自动修复不会删除浏览器密码、USB 历史、无线网络或手机热点历史。

## 七、备份、重复运行和回滚

首次成功进入修复前，程序将防火墙配置、受管规则、服务状态、服务启动类型、RDP 和 NetBIOS 原始状态保存到：

```text
%ProgramData%\SecurityRemediator\backup-v2.state
```

后续重复运行不会覆盖有效的首次备份。防火墙同名重复规则会收敛为每项一条；已经符合的项目不会重复修改。若设置被域策略或安全软件覆盖，复检会标记失败，不会持续争抢策略。

`/rollback` 只恢复本程序管理的系统配置，不恢复已经删除的浏览器密码、USB 历史或无线网络历史。

## 八、违规记录清理版

目录内必须同时保留 `record-cleaner.exe`、`cleanup-remediator.ps1` 和 `wireless-remediator.ps1`。

由待清理数据所属的当前用户右键 `record-cleaner.exe`，选择“以管理员身份运行”，阅读范围后输入小写 `yes`。不要以 SYSTEM 身份运行。

清理范围：

- 当前用户 Edge、Chrome、Firefox 的已保存密码记录。
- 已断开的 USBSTOR 存储设备历史；当前仍连接的设备不会强制删除。
- 已保存 Wi-Fi 配置、明确判定为无线的 NetworkList 历史，并禁用无线网卡。

有线网络历史不处理；无法确定类型的网络历史只列出供人工确认。无线清理会中断当前无线连接，必须先确认有线网络可用。清理不可通过系统修复回滚。

程序生成 `cleanup-report_IP_MAC_时间.html` 临时报告。清理后必须重新运行现场检查，不能只以临时报告作为最终结论。

## 九、报告说明

检查报告文件名：

```text
verification-report_IP_MAC_时间.html
verification-report_IP_MAC_时间.json
```

组合报告依次列出修复前检查、每项修复动作、修复后复检。JSON 顶层 `summary` 和 `details` 始终代表修复后的最终结果，便于旧版整理和 Excel 工具继续读取；新增的 `before` 和 `remediation` 保存修复前和修复过程。

“端口外部连通性”只能由另一台电脑对目标终端测试。本机监听记录不等同于端口已经能够从外部访问，因此该项可能显示“需复核”。

## 十、报告管理工具

### 删除同一终端的旧报告

把 `ftp-report-pruner-x64.exe` 放到 FTP 报告目录并运行。程序按终端身份分组，只保留时间最新的一组 HTML/JSON。显示待删除清单后，输入小写 `yes` 才会删除。删除前建议备份报告目录。

### 生成 Excel 问题汇总

把 `report-issue-exporter-x64.exe` 放到已整理好的报告目录并运行。它读取最新 JSON，以 IP 为基准每台终端一行生成 Excel，并在后面增加各类问题终端数量汇总。运行前应先整理旧报告，避免重复统计。

## 十一、退出码

现场版：`0` 成功或合规；`1` 修复、回滚或报告未完整成功；`3` 权限不足；`5` 只检查或未确认修复时发现异常。

FTP 版：`0` 成功；`1` 修复不完整；`2` 参数或 FTP 配置错误；`3` 权限不足；`5` 审计发现异常；`6` 修复成功但上传失败；`7` 本地操作存在异常且上传失败。

网管系统可依据进程退出码判断静默程序是否运行结束；进程退出即代表本次执行完成。详细情况以 `upload-status.json` 和检查报告为准。

## 十二、兼容性与验收说明

开发环境已完成 x86/x64 构建、共享检查一致性、报告质量、受管程序 Windows 7 静态导入检查、报告整理和 Excel 汇总测试。正式交付使用 x86 通用版。

静态导入检查不等同于真实 Windows 7 验收。正式上线前仍需在 Windows 7 SP1 x86/x64、Windows 10 x86/x64、Windows 11 x64 真机或虚拟机验证，并从另一台电脑测试端口不可达、普通网页访问和客户端出站访问正常。对承担 FTP 扫描接收业务的终端，还必须先用一台样机验证扫描设备控制连接、认证、数据连接和文件落盘，再扩大推送范围。

## 十三、版权

Copyright © 倚栏听雨。保留版权信息。具体授权边界以交付目录中的 `LICENSE` 为准。
