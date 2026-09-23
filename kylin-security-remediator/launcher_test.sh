#!/bin/sh
set -eu

PATH="/usr/bin:/bin:$PATH"

workspace_dir=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
delivery_dir="$workspace_dir/delivery/银河麒麟版/客户端"

test_launcher() {
    launcher_name=$1
    expected_mode=$2
    arch_name=$3
    expected_binary=$4

    fixture_dir=$(mktemp -d)
    trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM

    cp "$delivery_dir/$launcher_name" "$fixture_dir/$launcher_name"

    mkdir "$fixture_dir/fake-bin"
    cat >"$fixture_dir/fake-bin/uname" <<EOF
#!/bin/sh
printf '%s\n' '$arch_name'
EOF
    cat >"$fixture_dir/fake-bin/id" <<'EOF'
#!/bin/sh
printf '0\n'
EOF
    cat >"$fixture_dir/$expected_binary" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" >"$(dirname "$0")/invocation.txt"
EOF
    chmod +x "$fixture_dir/$launcher_name" "$fixture_dir/$expected_binary" "$fixture_dir/fake-bin/uname" "$fixture_dir/fake-bin/id"

    PATH="$fixture_dir/fake-bin:$PATH" "$fixture_dir/$launcher_name" </dev/null

    expected_output="$fixture_dir/reports"
    actual=$(sed -n '1p' "$fixture_dir/invocation.txt")
    [ "$actual" = "$expected_mode" ]
    actual=$(sed -n '2p' "$fixture_dir/invocation.txt")
    [ "$actual" = "--output" ]
    actual=$(sed -n '3p' "$fixture_dir/invocation.txt")
    [ "$actual" = "$expected_output" ]

    rm -rf "$fixture_dir"
    trap - EXIT HUP INT TERM
}

test_ftp_launcher() {
    arch_name=$1
    expected_binary=$2

    fixture_dir=$(mktemp -d)
    trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM

    cp "$delivery_dir/Run-FTP.sh" "$fixture_dir/Run-FTP.sh"
    sed -i \
        -e "s|^FTP_HOST=.*|FTP_HOST='192.0.2.10'|" \
        -e "s|^FTP_PORT=.*|FTP_PORT='13331'|" \
        -e "s|^FTP_USER=.*|FTP_USER='upload-user'|" \
        -e "s|^FTP_PASSWORD=.*|FTP_PASSWORD='test-password-2026!'|" \
        "$fixture_dir/Run-FTP.sh"

    mkdir "$fixture_dir/fake-bin"
    cat >"$fixture_dir/fake-bin/uname" <<EOF
#!/bin/sh
printf '%s\n' '$arch_name'
EOF
    cat >"$fixture_dir/fake-bin/id" <<'EOF'
#!/bin/sh
printf '0\n'
EOF
    cat >"$fixture_dir/$expected_binary" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" >"$(dirname "$0")/invocation.txt"
EOF
    chmod +x "$fixture_dir/Run-FTP.sh" "$fixture_dir/$expected_binary" "$fixture_dir/fake-bin/uname" "$fixture_dir/fake-bin/id"

    PATH="$fixture_dir/fake-bin:$PATH" "$fixture_dir/Run-FTP.sh" </dev/null >"$fixture_dir/output.txt"

    expected_output="$fixture_dir/reports"
    expected_arguments="--ftp-host
192.0.2.10
--ftp-port
13331
--ftp-user
upload-user
--ftp-password
test-password-2026!
--output
$expected_output"
    actual_arguments=$(cat "$fixture_dir/invocation.txt")
    [ "$actual_arguments" = "$expected_arguments" ]
    ! grep -F 'test-password-2026!' "$fixture_dir/output.txt" >/dev/null

    rm -rf "$fixture_dir"
    trap - EXIT HUP INT TERM
}

for arch_case in 'x86_64:kylin-onsite-amd64' 'aarch64:kylin-onsite-arm64'; do
    arch_name=${arch_case%%:*}
    expected_binary=${arch_case#*:}
    test_launcher Run-Audit.sh --audit "$arch_name" "$expected_binary"
    test_launcher Run-Repair.sh --repair "$arch_name" "$expected_binary"
done

for arch_case in 'x86_64:kylin-ftp-amd64' 'aarch64:kylin-ftp-arm64'; do
    arch_name=${arch_case%%:*}
    expected_binary=${arch_case#*:}
    test_ftp_launcher "$arch_name" "$expected_binary"
done

printf 'launcher tests passed\n'
