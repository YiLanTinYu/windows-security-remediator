# 银河麒麟现场运维使用说明

本目录包含现场检查、现场修复、FTP 报告回传和人工清理程序。

## 1. 查询架构

```bash
uname -m
```

- `x86_64` 使用文件名带 `amd64` 的程序。
- `aarch64` 或 `arm64` 使用文件名带 `arm64` 的程序。
- `Run-Audit.sh` 和 `Run-Repair.sh` 会自动选择架构，因此混合终端交付时应保留两种架构程序。

## 2. 只读检查

```bash
chmod +x ./Run-Audit.sh
sudo sh ./Run-Audit.sh
```

只生成检查报告，不修改系统。HTML 和 JSON 保存在当前目录的 `reports`。

## 3. 检查并修复

```bash
chmod +x ./Run-Repair.sh
sudo sh ./Run-Repair.sh
```

该脚本直接执行“修复前检查 → 修复 → 即时复检”，不会再次询问 `yes`。运行前必须确认停止 SSH、Samba、远程桌面或无线不会中断现场运维通道。

## 4. 现场检查修复并通过 FTP 回传

首次使用时，用文本编辑器打开 `Run-FTP.sh`，只修改文件顶部的以下四项：

```text
FTP_HOST='接收端IPv4'
FTP_PORT='控制端口'
FTP_USER='仅上传账号'
FTP_PASSWORD='密码'
```

地址、端口和账号密码必须与既有 Windows FTP 接收端一致。填写完成后运行：

```bash
chmod 700 ./Run-FTP.sh
sudo sh ./Run-FTP.sh
```

脚本会自动选择 `kylin-ftp-amd64` 或 `kylin-ftp-arm64`，执行修复前检查、修复、复检并上传报告。本地 HTML、JSON 和 `upload-status_*.json` 保存在 `reports`，上传失败时也不会删除。

账号密码以明文保存在脚本中，因此必须限制脚本权限，不得使用 `sh -x` 运行，不得把填写过真实密码的脚本上传到代码仓库或转发给无关人员。任务结束后应按本单位凭据管理要求保管或清除已填写的脚本。

查看最新上传状态：

```bash
sudo ls -lt ./reports
status_file=$(sudo sh -c 'ls -t ./reports/upload-status_*.json 2>/dev/null | head -n 1')
if [ -n "$status_file" ]; then
  sudo cat "$status_file"
fi
```

- `"status": "uploaded"` 表示上传成功。
- FTP `530` 表示已经连到接收端，但账号或密码不正确。
- `No route to host` 或连接超时应检查路由、VLAN、CEMS/iptables、交换机 ACL 和接收端允许来源网段。
- FTP `425`、`426` 或登录后超时应检查接收端被动端口范围和沿途防火墙。

把 `<FTP_SERVER>` 和端口替换为 `Run-FTP.sh` 顶部的实际接收端参数，不要把账号或密码复制到排错命令中：

```bash
FTP_SERVER='<FTP_SERVER>'
FTP_PORT='12221'
ip addr
ip route get "$FTP_SERVER"
ping -c 3 "$FTP_SERVER"
ip neigh show "$FTP_SERVER"
timeout 5 bash -c "exec 3<>/dev/tcp/$FTP_SERVER/$FTP_PORT; head -n 1 <&3"
```

最后一条命令显示 `220` 开头的 FTP 欢迎信息，表示路由和控制端口已连通。`ping` 失败不能单独证明 FTP 不通，因为网络设备可能禁止 ICMP，应以控制端口结果为准。

- `No route to host`：检查本机地址、掩码、网关、VLAN 和路由。
- 控制端口超时：检查终端 CEMS/iptables、交换机 ACL、接收端防火墙以及接收端允许来源网段。
- `Connection refused`：目标可达，但 FTP 接收进程未监听该端口，或主机防火墙主动拒绝。
- 同一程序只有部分终端失败：将失败终端的源 IP、上述命令输出、最新 `upload-status_*.json` 和失败时间交给接收端管理员，与成功终端逐项比较。

如果本地 HTML/JSON 已生成但上传状态为失败，检查和修复结果仍然有效，可先人工取回报告；如果没有生成上传状态文件，则检查脚本、对应架构的 `kylin-ftp-*` 文件和执行权限是否齐全。

## 5. 违规记录清理

先保存整改前报告并关闭浏览器。x86_64 终端运行：

```bash
chmod +x ./kylin-cleaner-amd64
sudo ./kylin-cleaner-amd64 --output ./cleanup-reports
```

ARM64 终端运行：

```bash
chmod +x ./kylin-cleaner-arm64
sudo ./kylin-cleaner-arm64 --output ./cleanup-reports
```

清理程序用于人工处理可识别的浏览器保存登录、非活动无线配置和能够安全单独识别的用户级 USB 最近记录。清理报告只是过程记录，完成后必须再次运行 `Run-Audit.sh` 生成最终复检报告。

## 6. 结果判断

| 退出码 | 含义                 |
| ---:| ------------------ |
| 0   | 流程完成；最终结论仍以报告为准    |
| 1   | 检查、修复、清理、复检或报告生成失败 |
| 2   | 参数错误或不支持的架构        |
| 3   | FTP 报告已保留在本地，但上传失败 |

退出码非零时保留终端输出和已生成报告。系统重启或 CEMS/KSC 策略刷新后应重新检查；外部端口阻断必须从另一台电脑验证。
