#!/bin/sh
set -u

# ===== FTP 配置：部署前必须修改下面四项 =====
FTP_HOST='CHANGE_ME'
FTP_PORT='12221'
FTP_USER='CHANGE_ME'
FTP_PASSWORD='CHANGE_ME'
# ==============================================

umask 077

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
script_path="$script_dir/$(basename "$0")"
report_dir="$script_dir/reports"

if [ -z "$FTP_HOST" ] || [ -z "$FTP_USER" ] || [ -z "$FTP_PASSWORD" ] || \
   [ "$FTP_HOST" = 'CHANGE_ME' ] || [ "$FTP_USER" = 'CHANGE_ME' ] || [ "$FTP_PASSWORD" = 'CHANGE_ME' ]; then
    printf '请先编辑 %s，填写 FTP_HOST、FTP_PORT、FTP_USER 和 FTP_PASSWORD。\n' "$script_path" >&2
    exit 2
fi

case "$FTP_PORT" in
    ''|*[!0-9]*)
        printf 'FTP_PORT 必须是 1 到 65535 之间的整数。\n' >&2
        exit 2
        ;;
esac
if [ "$FTP_PORT" -lt 1 ] || [ "$FTP_PORT" -gt 65535 ]; then
    printf 'FTP_PORT 必须是 1 到 65535 之间的整数。\n' >&2
    exit 2
fi

case "$(uname -m)" in
    x86_64|amd64)
        program="$script_dir/kylin-ftp-amd64"
        ;;
    aarch64|arm64)
        program="$script_dir/kylin-ftp-arm64"
        ;;
    *)
        printf '不支持的 CPU 架构：%s\n' "$(uname -m)" >&2
        exit 2
        ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    if ! command -v sudo >/dev/null 2>&1; then
        printf '需要管理员权限，但系统中未找到 sudo。请由管理员运行此脚本。\n' >&2
        exit 1
    fi
    exec sudo /bin/sh "$script_path"
fi

chmod 700 "$script_path" 2>/dev/null || true

if [ ! -f "$program" ]; then
    printf '未找到对应架构的 FTP 版程序：%s\n' "$program" >&2
    exit 1
fi

if [ ! -x "$program" ] && ! chmod +x "$program"; then
    printf '无法为 FTP 版程序添加执行权限：%s\n' "$program" >&2
    exit 1
fi

if ! mkdir -p "$report_dir"; then
    printf '无法创建报告目录：%s\n' "$report_dir" >&2
    exit 1
fi

printf '正在执行修复前检查、修复、即时复检和 FTP 报告回传。\n'
"$program" \
    --ftp-host "$FTP_HOST" \
    --ftp-port "$FTP_PORT" \
    --ftp-user "$FTP_USER" \
    --ftp-password "$FTP_PASSWORD" \
    --output "$report_dir"
status=$?

printf '执行结束，退出码：%s\n本地报告目录：%s\n' "$status" "$report_dir"
if [ "$status" -eq 3 ]; then
    printf 'FTP 回传失败，本地报告和上传状态文件已保留。\n' >&2
fi

if [ -t 0 ]; then
    printf '按回车键关闭窗口...'
    read -r _unused
fi

exit "$status"
