$ErrorActionPreference = 'Continue'
$base = Split-Path -Parent $MyInvocation.MyCommand.Path
$log = Join-Path $base 'verification.log'
function W([string]$s) { Add-Content -LiteralPath $log -Value $s -Encoding UTF8 }
W ('=' * 60); W ("SecurityRemediator 验证开始：{0}" -f (Get-Date)); W ""
W '[1] 检查 Server 文件共享服务（LanmanServer）'
sc.exe query LanmanServer 2>&1 | ForEach-Object { W $_ }
sc.exe qc LanmanServer 2>&1 | ForEach-Object { W $_ }
try { $s=Get-Service LanmanServer -ErrorAction Stop; W ("结果：状态={0}，启动类型={1}" -f $s.Status,$s.StartType) } catch { W '结果：无法读取 Server 服务。' }
W ''
W '[2] 检查远程桌面服务（TermService）'
sc.exe query TermService 2>&1 | ForEach-Object { W $_ }
sc.exe qc TermService 2>&1 | ForEach-Object { W $_ }
try { $s=Get-Service TermService -ErrorAction Stop; W ("结果：状态={0}，启动类型={1}" -f $s.Status,$s.StartType) } catch { W '结果：无法读取远程桌面服务。' }
W ''
W '[3] 检查远程桌面注册表配置'
reg.exe query 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections 2>&1 | ForEach-Object { W $_ }
W '预期：fDenyTSConnections 为 0x1。'; W ''
W '[4] 检查防火墙规则'
netsh.exe advfirewall firewall show rule name=all 2>&1 | Select-String -Pattern 'SecurityRemediator|22|135|136|137|138|139|445|3389' | ForEach-Object { W $_.Line }
W '预期：存在 SecurityRemediator 入站阻断规则。'; W ''
W '[5] 检查 NetBIOS 配置'
reg.exe query 'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' /s /v NetbiosOptions 2>&1 | ForEach-Object { W $_ }
W '预期：各网卡 NetbiosOptions 为 0x2。'; W ''
W '[6] 检查本机 TCP 监听（仅供参考）'
netstat.exe -ano | Select-String ':135|:139|:445|:3389' | ForEach-Object { W $_.Line }
W '注意：最终应从另一台电脑测试入站连接。'; W ("验证结束：{0}" -f (Get-Date)); Write-Host "验证完成，日志：$log"
