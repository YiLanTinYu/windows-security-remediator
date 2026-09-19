package platform_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/platform"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/usb"
)

func TestUSBProbeFindsCurrentStorageThroughSysfsSymlinks(t *testing.T) {
	root := t.TempDir()
	device := filepath.Join(root, "sys", "devices", "pci0000:00", "usb1", "1-1")
	deviceInterface := filepath.Join(root, "sys", "devices", "pci0000:00", "usb1", "1-1:1.0")
	bus := filepath.Join(root, "sys", "bus", "usb", "devices")
	for _, directory := range []string{device, deviceInterface, bus, filepath.Join(root, "run", "udev", "data"), filepath.Join(root, "proc", "self")} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for path, contents := range map[string]string{
		filepath.Join(device, "manufacturer"):             "aigo\n",
		filepath.Join(device, "product"):                  "U391\n",
		filepath.Join(device, "serial"):                   "SERIAL-001\n",
		filepath.Join(deviceInterface, "bInterfaceClass"): "08\n",
		filepath.Join(root, "proc", "self", "mountinfo"):  "",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../../../devices/pci0000:00/usb1/1-1", filepath.Join(bus, "1-1")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../../devices/pci0000:00/usb1/1-1:1.0", filepath.Join(bus, "1-1:1.0")); err != nil {
		t.Fatal(err)
	}

	probe := platform.USBProbe{
		Root:     os.DirFS(root),
		RootPath: root,
		Journal: func(context.Context) ([]byte, error) {
			return []byte("Linux fixture\n"), nil
		},
	}
	results, err := probe.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sysfs := sourceByName(t, results, "当前设备（sysfs）")
	if sysfs.Status != usb.StatusFound || len(sysfs.Records) != 1 {
		t.Fatalf("sysfs result = %#v, want one currently connected USB storage device", sysfs)
	}
	if sysfs.Records[0].Product != "U391" || sysfs.Records[0].Serial != "SERIAL-001" {
		t.Fatalf("sysfs record = %#v", sysfs.Records[0])
	}
}

func TestUSBProbeFindsMountedUSBBlockDeviceWithoutUdevProperties(t *testing.T) {
	root := t.TempDir()
	device := filepath.Join(root, "sys", "devices", "pci0000:00", "usb2", "2-3", "2-3.4")
	deviceInterface := filepath.Join(device, "2-3.4:1.0")
	blockDevice := filepath.Join(deviceInterface, "host1", "target1:0:0", "1:0:0:0", "block", "sdb")
	usbBus := filepath.Join(root, "sys", "bus", "usb", "devices")
	blockClass := filepath.Join(root, "sys", "class", "block")
	for _, directory := range []string{device, deviceInterface, blockDevice, usbBus, blockClass, filepath.Join(root, "run", "udev", "data"), filepath.Join(root, "proc", "self")} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for path, contents := range map[string]string{
		filepath.Join(device, "manufacturer"):             "USB\n",
		filepath.Join(device, "product"):                  "SanDisk 3.2Gen1\n",
		filepath.Join(deviceInterface, "bInterfaceClass"): "08\n",
		filepath.Join(blockDevice, "dev"):                 "8:16\n",
		filepath.Join(blockDevice, "device", "model"):     "SanDisk 3.2Gen1\n",
		filepath.Join(root, "proc", "self", "mountinfo"):  "36 29 8:16 / /media/USB rw,nosuid,nodev - vfat /dev/sdb rw\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../../../devices/pci0000:00/usb2/2-3/2-3.4", filepath.Join(usbBus, "2-3.4")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../../devices/pci0000:00/usb2/2-3/2-3.4/2-3.4:1.0", filepath.Join(usbBus, "2-3.4:1.0")); err != nil {
		t.Fatal(err)
	}
	blockTarget := "../../devices/pci0000:00/usb2/2-3/2-3.4/2-3.4:1.0/host1/target1:0:0/1:0:0:0/block/sdb"
	if err := os.Symlink(blockTarget, filepath.Join(blockClass, "sdb")); err != nil {
		t.Fatal(err)
	}

	probe := platform.USBProbe{
		Root:     os.DirFS(root),
		RootPath: root,
		Journal: func(context.Context) ([]byte, error) {
			return []byte("Linux fixture\n"), nil
		},
	}
	results, err := probe.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocks := sourceByName(t, results, "当前块设备（sysfs）")
	if blocks.Status != usb.StatusFound || len(blocks.Records) != 1 || blocks.Records[0].Detail != "/dev/sdb" {
		t.Fatalf("block result = %#v", blocks)
	}
	mounts := sourceByName(t, results, "当前挂载（mountinfo）")
	if mounts.Status != usb.StatusFound || len(mounts.Records) != 1 || mounts.Records[0].Detail != "/dev/sdb → /media/USB" {
		t.Fatalf("mount result = %#v", mounts)
	}
}
