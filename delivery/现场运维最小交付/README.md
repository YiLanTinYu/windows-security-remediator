# 现场运维交付包

本目录只供现场运维人员进行本机检查、人工确认修复和违规记录清理。程序均在终端本地运行，不安装服务、不创建开机启动项，也不需要额外安装运行库。

## 目录

```text
Windows
├─ 01-现场检查修复
│  ├─ onsite-check-repair.exe
│  └─ README.md
├─ 02-违规记录清理
│  ├─ record-cleaner.exe
│  ├─ record-cleaner-x64.exe
│  ├─ cleanup-remediator.ps1
│  ├─ wireless-remediator.ps1
│  └─ README.md
└─ 03-FTP回传排错说明
   └─ README.md

银河麒麟
├─ Run-Audit.sh
├─ Run-Repair.sh
├─ Run-FTP.sh
├─ kylin-onsite-amd64
├─ kylin-onsite-arm64
├─ kylin-ftp-amd64
├─ kylin-ftp-arm64
├─ kylin-cleaner-amd64
├─ kylin-cleaner-arm64
└─ README.md
```

## 现场操作原则

1. 先执行只检查并保存整改前报告。
2. 核对修复不会中断当前远程运维通道后，再执行修复。
3. 浏览器、USB 和无线记录由数据所属用户人工确认后清理。
4. 修复或清理后再次执行只检查，保存最终复检报告。
5. 高危端口是否真正不可达，应从另一台电脑进行外部探测。

银河麒麟 FTP 现场运行版具有远程回传功能。运维人员在终端现场运行检查修复程序，再由程序把报告上传到既有 Windows FTP 接收端；本包不包含接收端程序和生产凭据。

Windows FTP 静默程序适合网管推送，不放入现场最小交付包；`Windows\03-FTP回传排错说明` 仅供现场排查无法回传的终端。

详细命令见各程序目录中的 `README.md`。交付前可用根目录的 `SHA256SUMS.txt` 校验文件完整性。
