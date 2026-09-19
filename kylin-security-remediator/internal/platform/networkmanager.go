package platform

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/wireless"
)

type NMCLIBackend struct {
	nmcli           string
	connectionRoots []string
}

func NewNMCLIBackend() NMCLIBackend {
	return NMCLIBackend{
		nmcli: "/usr/bin/nmcli",
		connectionRoots: []string{
			"/etc/NetworkManager/system-connections",
			"/run/NetworkManager/system-connections",
		},
	}
}

func (b NMCLIBackend) Snapshot(ctx context.Context) (wireless.State, error) {
	radioOutput, err := b.run(ctx, "radio", "wifi")
	if err != nil {
		return wireless.State{}, fmt.Errorf("读取无线开关: %w", err)
	}
	deviceOutput, err := b.run(ctx, "-t", "-f", "DEVICE,TYPE,STATE", "device", "status")
	if err != nil {
		return wireless.State{}, fmt.Errorf("读取网卡: %w", err)
	}
	profileOutput, err := b.run(ctx, "-t", "-f", "UUID,NAME,TYPE,DEVICE", "connection", "show")
	if err != nil {
		return wireless.State{}, fmt.Errorf("读取网络配置: %w", err)
	}
	state := wireless.State{RadioEnabled: strings.TrimSpace(string(radioOutput)) == "enabled"}
	for _, line := range nonemptyLines(string(deviceOutput)) {
		fields := splitNMCLI(line)
		if len(fields) < 3 {
			return wireless.State{}, fmt.Errorf("无法解析网卡记录: %q", line)
		}
		kind := networkKind(fields[1])
		deviceState := fields[2]
		state.Devices = append(state.Devices, wireless.Device{
			Name: fields[0], Kind: kind,
			Enabled: deviceState != "unavailable" && deviceState != "unmanaged",
		})
	}
	for _, line := range nonemptyLines(string(profileOutput)) {
		fields := splitNMCLI(line)
		if len(fields) < 4 {
			return wireless.State{}, fmt.Errorf("无法解析网络配置记录: %q", line)
		}
		state.Profiles = append(state.Profiles, wireless.Profile{
			UUID: fields[0], Name: fields[1], Kind: networkKind(fields[2]),
			Active: fields[3] != "" && fields[3] != "--",
		})
	}
	return state, nil
}

func (b NMCLIBackend) Backup(_ context.Context, profile wireless.Profile) (wireless.Backup, error) {
	path, err := b.findConnectionFile(profile.UUID)
	if err != nil {
		return wireless.Backup{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return wireless.Backup{}, fmt.Errorf("读取配置文件状态: %w", err)
	}
	if !info.Mode().IsRegular() {
		return wireless.Backup{}, fmt.Errorf("配置文件不是普通文件: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return wireless.Backup{}, fmt.Errorf("读取配置文件: %w", err)
	}
	return wireless.Backup{Profile: profile, Path: path, Data: data, Mode: uint32(info.Mode().Perm())}, nil
}

func (b NMCLIBackend) findConnectionFile(uuid string) (string, error) {
	if strings.TrimSpace(uuid) == "" {
		return "", fmt.Errorf("网络配置 UUID 为空")
	}
	for _, root := range b.connectionRoots {
		entries, err := os.ReadDir(root)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("读取 NetworkManager 配置目录 %s: %w", root, err)
		}
		for _, entry := range entries {
			path := filepath.Join(root, entry.Name())
			info, statErr := os.Lstat(path)
			if statErr != nil {
				return "", fmt.Errorf("读取网络配置文件状态 %s: %w", path, statErr)
			}
			if !info.Mode().IsRegular() {
				continue
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return "", fmt.Errorf("读取网络配置文件 %s: %w", path, readErr)
			}
			if networkManagerUUID(data) == uuid {
				return path, nil
			}
		}
	}
	return "", fmt.Errorf("未找到 UUID 为 %s 的 NetworkManager 配置文件，拒绝无备份清理", uuid)
}

func networkManagerUUID(data []byte) string {
	section := ""
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		if section != "connection" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if found && strings.EqualFold(strings.TrimSpace(key), "uuid") {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (b NMCLIBackend) Delete(ctx context.Context, profile wireless.Profile) error {
	_, err := b.run(ctx, "connection", "delete", "uuid", profile.UUID)
	return err
}

func (b NMCLIBackend) SetRadio(ctx context.Context, enabled bool) error {
	value := "off"
	if enabled {
		value = "on"
	}
	_, err := b.run(ctx, "radio", "wifi", value)
	return err
}

func (b NMCLIBackend) Restore(ctx context.Context, backup wireless.Backup) error {
	dir := filepath.Dir(backup.Path)
	temp, err := os.CreateTemp(dir, ".security-remediator-restore-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	mode := os.FileMode(backup.Mode)
	if mode == 0 {
		mode = 0o600
	}
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(backup.Data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, backup.Path); err != nil {
		return err
	}
	_, err = b.run(ctx, "connection", "reload")
	return err
}

func (b NMCLIBackend) run(ctx context.Context, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, b.nmcli, args...)
	command.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func networkKind(value string) wireless.Kind {
	switch value {
	case "wifi", "wireless", "802-11-wireless":
		return wireless.KindWireless
	case "ethernet", "802-3-ethernet":
		return wireless.KindWired
	default:
		return wireless.KindUnknown
	}
}

func nonemptyLines(value string) []string {
	var result []string
	for _, line := range strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n") {
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func splitNMCLI(line string) []string {
	var fields []string
	var current strings.Builder
	escaped := false
	for _, char := range line {
		if escaped {
			current.WriteRune(char)
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		if char == ':' {
			fields = append(fields, current.String())
			current.Reset()
			continue
		}
		current.WriteRune(char)
	}
	if escaped {
		current.WriteRune('\\')
	}
	return append(fields, current.String())
}
