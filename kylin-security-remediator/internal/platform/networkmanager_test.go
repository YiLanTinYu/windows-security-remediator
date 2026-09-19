package platform

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/wireless"
)

func TestNMCLIBackupFindsConnectionFileByUUID(t *testing.T) {
	root := t.TempDir()
	wiredPath := filepath.Join(root, "wired.nmconnection")
	wifiPath := filepath.Join(root, "office-wifi.nmconnection")
	if err := os.WriteFile(wiredPath, []byte("[connection]\nid=Wired\nuuid=wired-uuid\ntype=ethernet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wifiData := []byte("# managed by NetworkManager\n[connection]\nid=Office Wi-Fi\nuuid=wifi-uuid\ntype=wifi\n\n[wifi]\nssid=Office\n")
	if err := os.WriteFile(wifiPath, wifiData, 0o600); err != nil {
		t.Fatal(err)
	}
	backend := NMCLIBackend{connectionRoots: []string{root}}

	backup, err := backend.Backup(context.Background(), wireless.Profile{UUID: "wifi-uuid", Name: "Office Wi-Fi"})
	if err != nil {
		t.Fatalf("Backup() error = %v", err)
	}
	if backup.Path != wifiPath {
		t.Fatalf("backup path = %q, want %q", backup.Path, wifiPath)
	}
	if string(backup.Data) != string(wifiData) {
		t.Fatalf("backup data = %q", backup.Data)
	}
}

func TestNMCLIBackupRefusesDeleteWhenUUIDHasNoConfigurationFile(t *testing.T) {
	backend := NMCLIBackend{connectionRoots: []string{t.TempDir()}}

	_, err := backend.Backup(context.Background(), wireless.Profile{UUID: "missing-uuid", Name: "Missing Wi-Fi"})
	if err == nil || !strings.Contains(err.Error(), "未找到") {
		t.Fatalf("Backup() error = %v, want not found", err)
	}
}
