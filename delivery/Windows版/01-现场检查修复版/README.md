# Windows 现场检查修复版使用说明

入口：`onsite-check-repair.exe`
版本：2.0.3

## 使用场景

用于运维人员在终端现场查看检查结果、确认后修复，或只生成检查报告。程序不需要其他依赖。

## 标准操作

1. 将本目录整体复制到目标终端的本地磁盘。
2. 右键 `onsite-check-repair.exe`，选择“以管理员身份运行”。
3. 程序先完成修复前检查并显示通过、异常和需复核数量。
4. 输入小写 `yes` 执行修复；输入其他内容只保存检查结果，不修改系统。
5. 修复完成后程序自动复检，在本目录生成 HTML 和 JSON，并默认打开 HTML。

## 命令行

```powershell
# 只检查，不修改
.\onsite-check-repair.exe /audit-only

# 恢复首次修复前备份；程序仍会要求输入小写 yes
.\onsite-check-repair.exe /rollback

# 不自动打开报告、不等待按键
.\onsite-check-repair.exe /no-open /no-pause

# 适合脚本调用的只检查模式
.\onsite-check-repair.exe /audit-only /no-open /no-pause
```

## 输出和退出码

报告文件为 `verification-report_<IP>_<MAC>_<时间戳>.html/.json`。

| 退出码 | 含义 |
|---:|---|
| 0 | 检查合规，或修复/回滚成功 |
| 1 | 修复、回滚或报告生成未完整成功 |
| 3 | 权限不足 |
| 5 | 只检查或未确认修复时发现异常 |

退出码 `5` 表示发现问题，不表示程序没有运行。

## 验收

- 确认 HTML 和 JSON 同时生成且终端 IP/MAC 正确。
- 修复后报告应同时保留“修复前”和“修复后”。
- 从另一台电脑验证高危入站端口不可达。
- 承担 FTP 扫描接收业务的终端必须额外验证扫描文件能够正常落盘。

详细修复边界见上级目录 `README.md`。
