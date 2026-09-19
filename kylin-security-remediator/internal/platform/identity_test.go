package platform_test

import (
	"context"
	"net"
	"testing"
	"testing/fstest"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/platform"
)

func TestIdentityReadsKylinReleaseAndSelectsUsableInterface(t *testing.T) {
	root := fstest.MapFS{
		"etc/os-release": {Data: []byte("PRETTY_NAME=\"Kylin V10 SP1\"\nKYLIN_RELEASE_ID=\"2403\"\n")},
	}
	probe := platform.IdentityProbe{
		Root:          root,
		Hostname:      func() (string, error) { return "kylin-pc", nil },
		Arch:          func() string { return "amd64" },
		Kernel:        func(context.Context) string { return "5.15.0-kylin" },
		EffectiveUser: func() string { return "root" },
		DesktopUser:   func(context.Context) string { return "zhangsan" },
		Interfaces: func() ([]platform.NetworkInterface, error) {
			return []platform.NetworkInterface{
				{Name: "lo", Up: true, Loopback: true, IP: "127.0.0.1"},
				{Name: "eno1", Kind: "有线", Up: true, IP: "192.0.2.20", MAC: net.HardwareAddr{0x18, 0x3d, 0x2d, 0xc6, 0x47, 0x7b}},
				{Name: "wlp2s0", Kind: "无线", Up: false, MAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 2}},
			}, nil
		},
	}

	got, err := probe.Identity(context.Background())
	if err != nil {
		t.Fatalf("Identity() error = %v", err)
	}
	if got.OS != "Kylin V10 SP1 (2403)" || got.Kernel != "5.15.0-kylin" || got.DesktopUser != "zhangsan" || got.EffectiveUser != "root" || got.IP != "192.0.2.20" || got.MAC != "18-3D-2D-C6-47-7B" {
		t.Fatalf("Identity() = %#v", got)
	}
	if len(got.Interfaces) != 3 || got.Interfaces[1].Kind != "有线" || got.Interfaces[2].Kind != "无线" {
		t.Fatalf("interfaces = %#v", got.Interfaces)
	}
}

func TestIdentityUsesFallbackAddressAndKeepsPhysicalInterfaceWithoutIPv4(t *testing.T) {
	root := fstest.MapFS{
		"etc/os-release": {Data: []byte("PRETTY_NAME=\"Kylin V10 SP1\"\n")},
	}
	mac := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x16}
	probe := platform.IdentityProbe{
		Root:          root,
		Hostname:      func() (string, error) { return "arm-pc", nil },
		Arch:          func() string { return "arm64" },
		EffectiveUser: func() string { return "root" },
		DesktopUser:   func(context.Context) string { return "test" },
		Interfaces: func() ([]platform.NetworkInterface, error) {
			return []platform.NetworkInterface{
				{Name: "lo", Kind: "回环", Up: true, Loopback: true, IP: "127.0.0.1"},
				{Name: "enp1s0", Kind: "有线", Up: true, MAC: mac},
			}, nil
		},
		FallbackInterfaces: func(context.Context) ([]platform.NetworkInterface, error) {
			return []platform.NetworkInterface{{Name: "enp1s0", Kind: "有线", Up: true, IP: "192.0.2.16", MAC: mac}}, nil
		},
	}

	got, err := probe.Identity(context.Background())
	if err != nil {
		t.Fatalf("Identity() error = %v", err)
	}
	if got.IP != "192.0.2.16" || got.MAC != "02-00-00-00-00-16" {
		t.Fatalf("identity fallback = %#v", got)
	}
	if len(got.Interfaces) != 2 || got.Interfaces[1].Name != "enp1s0" || got.Interfaces[1].MAC != "02-00-00-00-00-16" {
		t.Fatalf("interfaces = %#v", got.Interfaces)
	}
}
