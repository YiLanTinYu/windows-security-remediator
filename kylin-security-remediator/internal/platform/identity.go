package platform

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/core"
)

type NetworkInterface struct {
	Name     string
	Kind     string
	Up       bool
	Loopback bool
	IP       string
	MAC      net.HardwareAddr
}

type IdentityProbe struct {
	Root               fs.FS
	Hostname           func() (string, error)
	Arch               func() string
	Kernel             func(context.Context) string
	EffectiveUser      func() string
	DesktopUser        func(context.Context) string
	Interfaces         func() ([]NetworkInterface, error)
	FallbackInterfaces func(context.Context) ([]NetworkInterface, error)
}

func NewIdentityProbe() IdentityProbe {
	return IdentityProbe{
		Root:               os.DirFS("/"),
		Hostname:           os.Hostname,
		Arch:               func() string { return runtime.GOARCH },
		Kernel:             kernelVersion,
		EffectiveUser:      effectiveUsername,
		DesktopUser:        desktopUsername,
		Interfaces:         systemInterfaces,
		FallbackInterfaces: ipCommandInterfaces,
	}
}

func (p IdentityProbe) Identity(ctx context.Context) (core.Identity, error) {
	hostname, err := p.Hostname()
	if err != nil {
		return core.Identity{}, fmt.Errorf("读取计算机名: %w", err)
	}
	osName, err := readOSRelease(p.Root)
	if err != nil {
		return core.Identity{}, err
	}
	interfaces, err := p.Interfaces()
	if err != nil {
		return core.Identity{}, fmt.Errorf("读取网卡: %w", err)
	}
	identity := core.Identity{Hostname: hostname, OS: osName, Arch: p.Arch()}
	if p.Kernel != nil {
		identity.Kernel = p.Kernel(ctx)
	}
	if p.EffectiveUser != nil {
		identity.EffectiveUser = p.EffectiveUser()
	}
	if p.DesktopUser != nil {
		identity.DesktopUser = p.DesktopUser(ctx)
	}
	preferredInterface := ""
	if !hasUsableInterface(interfaces) && p.FallbackInterfaces != nil {
		fallback, fallbackErr := p.FallbackInterfaces(ctx)
		if fallbackErr != nil {
			identity.NetworkStatus = "备用网络读取失败：" + fallbackErr.Error()
		} else {
			interfaces = mergeInterfaces(interfaces, fallback)
			for _, item := range fallback {
				if item.Up && !item.Loopback && item.IP != "" && len(item.MAC) > 0 {
					preferredInterface = item.Name
					break
				}
			}
		}
	}
	for _, item := range interfaces {
		mac := formatMAC(item.MAC)
		identity.Interfaces = append(identity.Interfaces, core.NetworkInterface{
			Name: item.Name, Kind: item.Kind, Up: item.Up, IP: item.IP, MAC: mac,
		})
		if identity.IP != "" || !item.Up || item.Loopback || item.IP == "" || len(item.MAC) == 0 || (preferredInterface != "" && item.Name != preferredInterface) {
			continue
		}
		identity.IP = item.IP
		identity.MAC = mac
	}
	if identity.MAC == "" {
		for _, item := range interfaces {
			if item.Up && !item.Loopback && len(item.MAC) > 0 {
				identity.MAC = formatMAC(item.MAC)
				break
			}
		}
	}
	if identity.IP == "" && identity.NetworkStatus == "" {
		identity.NetworkStatus = "未发现带IPv4地址的活动非回环网卡"
	}
	return identity, nil
}

func hasUsableInterface(interfaces []NetworkInterface) bool {
	for _, item := range interfaces {
		if item.Up && !item.Loopback && item.IP != "" && len(item.MAC) > 0 {
			return true
		}
	}
	return false
}

func mergeInterfaces(primary, fallback []NetworkInterface) []NetworkInterface {
	result := append([]NetworkInterface(nil), primary...)
	for _, candidate := range fallback {
		merged := false
		for index := range result {
			if result[index].Name != candidate.Name {
				continue
			}
			if result[index].IP == "" {
				result[index].IP = candidate.IP
			}
			if len(result[index].MAC) == 0 {
				result[index].MAC = candidate.MAC
			}
			if result[index].Kind == "" || result[index].Kind == "未知" {
				result[index].Kind = candidate.Kind
			}
			result[index].Up = result[index].Up || candidate.Up
			merged = true
			break
		}
		if !merged {
			result = append(result, candidate)
		}
	}
	return result
}

func formatMAC(mac net.HardwareAddr) string {
	return strings.ToUpper(strings.ReplaceAll(mac.String(), ":", "-"))
}

func kernelVersion(ctx context.Context) string {
	output, err := exec.CommandContext(ctx, "/bin/uname", "-r").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func effectiveUsername() string {
	current, err := user.Current()
	if err == nil && current.Username != "" {
		return current.Username
	}
	return os.Getenv("USER")
}

func desktopUsername(ctx context.Context) string {
	if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
		return name
	}
	output, err := exec.CommandContext(ctx, "/bin/loginctl", "list-sessions", "--no-legend").Output()
	if err == nil {
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 || fields[2] == "root" {
				continue
			}
			active, activeErr := exec.CommandContext(ctx, "/bin/loginctl", "show-session", fields[0], "--property=Active", "--value").Output()
			remote, remoteErr := exec.CommandContext(ctx, "/bin/loginctl", "show-session", fields[0], "--property=Remote", "--value").Output()
			if activeErr == nil && remoteErr == nil && strings.TrimSpace(string(active)) == "yes" && strings.TrimSpace(string(remote)) == "no" {
				return fields[2]
			}
		}
	}
	if name := os.Getenv("USER"); name != "" && name != "root" {
		return name
	}
	return effectiveUsername()
}

func readOSRelease(root fs.FS) (string, error) {
	file, err := root.Open("etc/os-release")
	if err != nil {
		return "", fmt.Errorf("读取 /etc/os-release: %w", err)
	}
	defer file.Close()
	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if ok {
			values[key] = strings.Trim(strings.TrimSpace(value), "\"")
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("解析 /etc/os-release: %w", err)
	}
	name := values["PRETTY_NAME"]
	if name == "" {
		name = values["NAME"]
	}
	if release := values["KYLIN_RELEASE_ID"]; release != "" {
		name += " (" + release + ")"
	}
	return name, nil
}

func systemInterfaces() ([]NetworkInterface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var result []NetworkInterface
	for _, item := range interfaces {
		addresses, addressErr := item.Addrs()
		entry := NetworkInterface{
			Name: item.Name, Kind: systemInterfaceKind(item), Up: item.Flags&net.FlagUp != 0,
			Loopback: item.Flags&net.FlagLoopback != 0, MAC: item.HardwareAddr,
		}
		if addressErr == nil {
			for _, address := range addresses {
				ip, _, parseErr := net.ParseCIDR(address.String())
				if parseErr == nil && ip != nil && ip.To4() != nil {
					entry.IP = ip.String()
					break
				}
			}
		}
		result = append(result, entry)
	}
	return result, nil
}

func ipCommandInterfaces(ctx context.Context) ([]NetworkInterface, error) {
	ipPath, err := exec.LookPath("ip")
	if err != nil {
		return nil, errors.New("未找到ip命令")
	}
	output, err := exec.CommandContext(ctx, ipPath, "-o", "-4", "addr", "show", "up", "scope", "global").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ip地址读取失败: %s", strings.TrimSpace(string(output)))
	}
	var result []NetworkInterface
	for _, line := range strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[2] != "inet" {
			continue
		}
		name := strings.SplitN(strings.TrimSuffix(fields[1], ":"), "@", 2)[0]
		ip, _, parseErr := net.ParseCIDR(fields[3])
		if parseErr != nil || ip.To4() == nil {
			continue
		}
		entry := NetworkInterface{Name: name, Kind: "未知", Up: true, IP: ip.String()}
		if item, lookupErr := net.InterfaceByName(name); lookupErr == nil {
			entry.MAC = item.HardwareAddr
			entry.Kind = systemInterfaceKind(*item)
		}
		result = append(result, entry)
	}
	return preferDefaultRoute(ctx, ipPath, result), nil
}

func preferDefaultRoute(ctx context.Context, ipPath string, interfaces []NetworkInterface) []NetworkInterface {
	output, err := exec.CommandContext(ctx, ipPath, "-4", "route", "show", "default").Output()
	if err != nil {
		return interfaces
	}
	fields := strings.Fields(string(output))
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] != "dev" {
			continue
		}
		name := fields[index+1]
		for interfaceIndex := range interfaces {
			if interfaces[interfaceIndex].Name == name {
				selected := interfaces[interfaceIndex]
				result := make([]NetworkInterface, 0, len(interfaces))
				result = append(result, selected)
				result = append(result, interfaces[:interfaceIndex]...)
				result = append(result, interfaces[interfaceIndex+1:]...)
				return result
			}
		}
	}
	return interfaces
}

func systemInterfaceKind(item net.Interface) string {
	if item.Flags&net.FlagLoopback != 0 {
		return "回环"
	}
	if _, err := os.Stat("/sys/class/net/" + item.Name + "/wireless"); err == nil {
		return "无线"
	}
	if _, err := os.Stat("/sys/class/net/" + item.Name + "/device"); err == nil {
		return "有线"
	}
	return "未知"
}
