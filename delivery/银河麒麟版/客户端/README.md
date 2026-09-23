# 银河麒麟客户端使用说明

## 1. 文件和架构

查询终端架构：

```bash
uname -m
```

- `x86_64`：使用 `amd64` 程序。
- `aarch64` 或 `arm64`：使用 `arm64` 程序。

一键脚本会自动选择架构。交付混合终端时保留两种架构程序；只交付一台已知架构终端时，也必须保留脚本及该脚本需要的对应程序。

## 2. 一键只读检查

需要：

```text
Run-Audit.sh
kylin-onsite-amd64
kylin-onsite-arm64
```

运行：

```bash
chmod +x ./Run-Audit.sh
sudo sh ./Run-Audit.sh
```

脚本自动申请 `sudo` 权限，只检查并把 HTML/JSON 写入同目录的 `reports`，不修改系统。退出码非零时先查看终端输出和报告，不要只凭窗口闪退判断。

## 3. 一键检查修复

需要：

```text
Run-Repair.sh
kylin-onsite-amd64
kylin-onsite-arm64
```

运行：

```bash
chmod +x ./Run-Repair.sh
sudo sh ./Run-Repair.sh
```

该脚本会直接执行“修复前检查 → 修复 → 即时复检”，不会再次询问 `yes`。运行前确认停止 SSH、Samba、远程桌面和关闭无线不会中断运维通道。

## 4. 现场交互程序

不使用脚本时可以直接运行对应架构程序：

```bash
chmod +x ./kylin-onsite-amd64
sudo ./kylin-onsite-amd64 --output ./reports
```

ARM64 将文件名改为 `kylin-onsite-arm64`。程序提示后，输入小写 `yes` 执行检查、修复和复检；其他输入只检查。也可显式指定：

```bash
sudo ./kylin-onsite-amd64 --audit --output ./reports
sudo ./kylin-onsite-amd64 --repair --output ./reports
```

## 5. 一键 FTP 检查修复回传

需要：

```text
Run-FTP.sh
kylin-ftp-amd64
kylin-ftp-arm64
```

首次使用：

1. 用文本编辑器打开 `Run-FTP.sh`。
2. 只修改文件顶部的 `FTP_HOST`、`FTP_PORT`、`FTP_USER`、`FTP_PASSWORD`。
3. 地址、端口和账号密码必须与当前 Windows FTP 接收端一致；不要另外建立麒麟专用参数。
4. 对脚本限制权限并运行：

```bash
chmod 700 ./Run-FTP.sh
sudo sh ./Run-FTP.sh
```

脚本会执行检查、修复、复检和被动 FTP 上传。本地 HTML、JSON 和上传状态文件保存在 `reports`，即使上传失败也不会删除。

账号和密码以明文保存在脚本中。必须使用专用上传账号、执行 `chmod 700`，不得把填写过密码的脚本上传到代码仓库或转发给无关人员，也不要使用 `sh -x` 运行。

手动运行示例：

```bash
sudo ./kylin-ftp-amd64 \
  --ftp-host <接收端IPv4> \
  --ftp-port <控制端口> \
  --ftp-user '<仅上传账号>' \
  --ftp-password '<密码>' \
  --output ./reports
```

ARM64 将程序名改为 `kylin-ftp-arm64`。四项 FTP 参数必须同时提供；完全不提供 FTP 参数时只在本地生成报告。普通 FTP 不加密，只限受控内网使用。

上传状态：

- `"status": "uploaded"`：回传成功。
- `"status": "failed"`：回传失败，查看 `error`。
- 出现 `dial tcp ... timeout/no route to host`：连接尚未到达 FTP 登录阶段，优先检查路由、ARP、防火墙/CEMS、VLAN、交换机 ACL 和接收端监听。
- 出现 FTP `530`：已经连到接收端，但账号或密码不正确。

### 回传失败现场排错

先记录本次退出码，再查看最新本地报告和上传状态：

```bash
sudo sh ./Run-FTP.sh
rc=$?
printf '退出码=%s\n' "$rc"
sudo ls -lt ./reports
status_file=$(sudo sh -c 'ls -t ./reports/upload-status_*.json 2>/dev/null | head -n 1')
if [ -n "$status_file" ]; then
  sudo cat "$status_file"
fi
```

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

最后一条命令显示 `220` 开头的 FTP 欢迎信息，表示路由和控制端口已经连通。`ping` 失败不能单独证明 FTP 不通，因为网络设备可能禁止 ICMP，应以控制端口结果为准。

按错误阶段判断：

- `No route to host`：检查本机地址、掩码、网关、VLAN 和路由。
- 控制端口超时：检查终端 CEMS/iptables、交换机 ACL、接收端防火墙以及接收端允许来源网段。
- `Connection refused`：目标可达，但 FTP 接收进程未监听该端口，或主机防火墙主动拒绝。
- FTP `530`：控制连接已经到达接收端，核对账号密码；不要使用 `sh -x`，也不要把密码贴入排错记录。
- FTP `425`、`426`，或登录后传输超时：检查接收端被动端口范围及沿途防火墙/ACL。
- 同一程序只有部分终端失败：把失败终端的源 IP、上述命令输出、最新 `upload-status_*.json` 和失败时间交给接收端管理员，与成功终端逐项比较。

如果本地 HTML/JSON 已生成但状态为失败，检查和修复结果仍然有效，可先人工取回报告；如果没有生成上传状态文件，则检查脚本、对应架构的 `kylin-ftp-*` 文件和执行权限是否齐全。

## 6. 违规记录清理

先保存整改前检查报告，再运行对应架构清理程序：

```bash
chmod +x ./kylin-cleaner-amd64
sudo ./kylin-cleaner-amd64 --output ./cleanup-reports
```

ARM64 将文件名改为 `kylin-cleaner-arm64`。清理范围包括可识别的浏览器保存登录、明确的非活动 Wi-Fi/热点配置，以及能够安全单独识别的用户级 USB 最近记录。当前 Wi-Fi、类型不明网络和系统级 USB 证据不会被强制删除。

清理完成后再次运行 `Run-Audit.sh`。`kylin-cleanup-report_*` 是过程报告，不能替代最终复检报告。

## 7. 退出码

| 退出码 | 含义                 |
| ---:| ------------------ |
| 0   | 流程完成；合规结论仍以报告为准    |
| 1   | 检查、修复、清理、复检或报告生成失败 |
| 2   | 参数错误或不支持的架构        |
| 3   | FTP 报告已保留在本地，但上传失败 |

## 8. 报告说明和限制

- `--output` 指定的是麒麟客户端本地目录，不是服务器目录。
- 报告使用 Windows 兼容的新格式，可由 Windows 报告管理工具统一读取。
- USB 日志条数、最近文件条数不能直接换算为使用过多少台 USB 设备。
- 浏览器检查只读取站点和账号元数据，不读取或输出密码。
- 检测到 CEMS 接管时，防火墙部分只审计 CEMS 覆盖情况；已覆盖显示正常，缺失项在 CEMS 管理端补充。
- 系统重启或安全策略刷新后应重新检查。
