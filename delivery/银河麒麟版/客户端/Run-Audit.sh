#!/bin/sh
set -u

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
script_path="$script_dir/$(basename "$0")"

case "$(uname -m)" in
    x86_64|amd64)
        program="$script_dir/kylin-onsite-amd64"
        ;;
    aarch64|arm64)
        program="$script_dir/kylin-onsite-arm64"
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

if [ ! -f "$program" ]; then
    printf '未找到对应架构的检查程序：%s\n' "$program" >&2
    exit 1
fi

if [ ! -x "$program" ] && ! chmod +x "$program"; then
    printf '无法为检查程序添加执行权限：%s\n' "$program" >&2
    exit 1
fi

report_dir="$script_dir/reports"
if ! mkdir -p "$report_dir"; then
    printf '无法创建报告目录：%s\n' "$report_dir" >&2
    exit 1
fi

printf '正在执行只读安全检查，不修改系统配置。\n'
"$program" --audit --output "$report_dir"
status=$?
printf '检查结束，退出码：%s\n报告目录：%s\n' "$status" "$report_dir"

if [ -t 0 ]; then
    printf '按回车键关闭窗口...'
    read -r _unused
fi

exit "$status"
