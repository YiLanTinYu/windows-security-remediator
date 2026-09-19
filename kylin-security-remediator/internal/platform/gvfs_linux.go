//go:build linux

package platform

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

func systemGVFSEntries(ctx context.Context, userID, path string) ([]string, error) {
	account, err := user.LookupId(userID)
	if err != nil {
		return nil, fmt.Errorf("无法识别GVFS目录所属用户: %w", err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("GVFS用户ID无效: %w", err)
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("GVFS用户组ID无效: %w", err)
	}
	command := exec.CommandContext(ctx, "/bin/ls", "-1A", "--", path)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	command.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if strings.Contains(strings.ToLower(message), "no such file") {
			return nil, fs.ErrNotExist
		}
		if strings.Contains(strings.ToLower(message), "permission denied") {
			return nil, fs.ErrPermission
		}
		if message == "" {
			message = err.Error()
		}
		return nil, errors.New(message)
	}
	var names []string
	for _, name := range strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n") {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}
