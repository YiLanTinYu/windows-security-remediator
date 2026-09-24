# Windows 违规记录清理版使用说明

入口：`record-cleaner.exe`
版本：2.0.1

## 必需文件

以下四个文件必须保持在同一目录：

```text
record-cleaner.exe
record-cleaner-x64.exe
cleanup-remediator.ps1
wireless-remediator.ps1
```

不要只复制入口 EXE，否则部分清理功能无法执行。`record-cleaner.exe` 是通用入口；64 位 Windows 清理 USB 设备历史时会自动调用 `record-cleaner-x64.exe`，以避免 WOW64 设备管理限制。

## 操作流程

1. 先运行检查程序并保存整改前 HTML/JSON 报告。
2. 关闭正在运行的浏览器。
3. 确认终端已经连接有线网络；无线清理可能立即中断 Wi-Fi。
4. 由待清理数据所属的当前用户右键 `record-cleaner.exe`，选择“以管理员身份运行”。不要以 SYSTEM 身份运行。
5. 阅读范围后输入小写 `yes`。IE 凭据清理检测到记录时会再次要求确认。
6. 保存生成的 `cleanup-report_*.html` 临时报告。
7. 再运行现场版 `/audit-only`，以新的正式检查报告确认最终状态。

## 清理范围

- 当前用户 Edge、Chrome、Firefox 的有效保存登录记录。
- 当前用户 IE Storage2 和明确带 `Microsoft_WinInet_` 标识的凭据。
- 已断开的 USBSTOR 存储设备历史；不会强制清理仍连接的设备。
- 已保存 Wi-Fi 配置、明确识别为无线的 NetworkList 历史，并禁用无线网卡。

有线网络历史不处理；类型不明确的网络只列出供人工确认。Windows“Web 凭据”可能被多个程序共用，工具只统计并标记“需人工处理”，不会整库删除。

## 风险和验收

- 清理属于不可逆删除，不包含在现场版 `/rollback` 中。
- 清理报告是过程记录，不是最终合规报告。
- 64 位 Windows 上若缺少 `record-cleaner-x64.exe`，USB 项会明确标记为“失败/需复核”，不会用 32 位程序冒险清理。
- 报告中仍有剩余或读取失败时，不得标记为已完成，应按提示人工复核。
- 重新运行现场只检查版，并核对浏览器、USB 和无线项目，才算完成验收。
