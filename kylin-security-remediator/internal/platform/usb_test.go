package platform_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/platform"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/usb"
)

func TestUSBProbeCleanSafeRejectsNonRecentFileLocator(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "home", "alice", "Documents", "data.xbel")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	content := `<xbel><bookmark href="file:///media/alice/USB/secret.txt"/></xbel>`
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	probe := platform.USBProbe{Root: os.DirFS(root), RootPath: root}

	err := probe.CleanSafe(context.Background(), []usb.Record{{
		Product: "forged", Detail: "file:///media/alice/USB/secret.txt",
		Locator: "home/alice/Documents/data.xbel", Cleanable: true,
	}})
	if err == nil {
		t.Fatal("CleanSafe() error = nil, want rejected locator")
	}
	after, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != content {
		t.Fatalf("unrelated file changed: %s", after)
	}
}

func TestUSBProbeFindsMassStorageInSysfsAndSeparatesReadableJournalWithNoHistory(t *testing.T) {
	root := fstest.MapFS{
		"sys/bus/usb/devices/1-1":                     {Mode: 0o755 | 1<<31},
		"sys/bus/usb/devices/1-1/manufacturer":        {Data: []byte("aigo\n")},
		"sys/bus/usb/devices/1-1/product":             {Data: []byte("U391\n")},
		"sys/bus/usb/devices/1-1/serial":              {Data: []byte("SERIAL-001\n")},
		"sys/bus/usb/devices/1-1:1.0":                 {Mode: 0o755 | 1<<31},
		"sys/bus/usb/devices/1-1:1.0/bInterfaceClass": {Data: []byte("08\n")},
	}
	probe := platform.USBProbe{
		Root: root,
		Journal: func(context.Context) ([]byte, error) {
			return []byte("Linux version 5.15.0\nnetwork device ready\n"), nil
		},
	}

	results, err := probe.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	sysfs := sourceByName(t, results, "当前设备（sysfs）")
	journal := sourceByName(t, results, "内核日志（journal）")
	recent := sourceByName(t, results, "用户级最近文件记录")
	if sysfs.Status != usb.StatusFound || journal.Status != usb.StatusNone || recent.Status != usb.StatusUnavailable {
		t.Fatalf("results = %#v", results)
	}
	if len(sysfs.Records) != 1 || sysfs.Records[0].Product != "U391" || sysfs.Records[0].Serial != "SERIAL-001" {
		t.Fatalf("sysfs records = %#v", sysfs.Records)
	}
}

func TestUSBProbeCleansOnlyRemovableEntriesFromUserRecentFiles(t *testing.T) {
	root := t.TempDir()
	recentPath := filepath.Join(root, "home", "alice", ".local", "share", "recently-used.xbel")
	if err := os.MkdirAll(filepath.Dir(recentPath), 0o755); err != nil {
		t.Fatal(err)
	}
	contents := `<?xml version="1.0" encoding="UTF-8"?>
<xbel version="1.0">
  <bookmark href="file:///media/alice/USB/report.txt"><title>USB report</title></bookmark>
  <bookmark href="file:///home/alice/Documents/work.txt"><title>Work</title></bookmark>
</xbel>`
	if err := os.WriteFile(recentPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	probe := platform.USBProbe{
		Root:     os.DirFS(root),
		RootPath: root,
		Journal: func(context.Context) ([]byte, error) {
			return []byte("Linux version fixture\n"), nil
		},
	}

	results, err := probe.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	recent := sourceByName(t, results, "用户级最近文件记录")
	if recent.Status != usb.StatusFound || len(recent.Records) != 1 {
		t.Fatalf("results = %#v", results)
	}
	if !recent.Records[0].Cleanable {
		t.Fatalf("record is not marked cleanable: %#v", recent.Records[0])
	}
	if err := probe.CleanSafe(context.Background(), recent.Records); err != nil {
		t.Fatalf("CleanSafe() error = %v", err)
	}
	after, err := os.ReadFile(recentPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), "/media/alice/USB/report.txt") {
		t.Fatalf("removable entry remains: %s", after)
	}
	if !strings.Contains(string(after), "/home/alice/Documents/work.txt") {
		t.Fatalf("ordinary recent file was removed: %s", after)
	}
}

func TestUSBProbeReportsMissingSysfsAsUnavailable(t *testing.T) {
	probe := platform.USBProbe{
		Root: fstest.MapFS{},
		Journal: func(context.Context) ([]byte, error) {
			return nil, nil
		},
	}
	results, err := probe.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if sourceByName(t, results, "当前设备（sysfs）").Status != usb.StatusUnavailable || sourceByName(t, results, "内核日志（journal）").Status != usb.StatusRotated {
		t.Fatalf("results = %#v", results)
	}
}

func sourceByName(t *testing.T, results []usb.SourceResult, name string) usb.SourceResult {
	t.Helper()
	for _, result := range results {
		if result.Name == name {
			return result
		}
	}
	t.Fatalf("missing source %q in %#v", name, results)
	return usb.SourceResult{}
}

func TestUSBProbeFindsUSBStorageInUdevDatabase(t *testing.T) {
	probe := platform.USBProbe{
		Root: fstest.MapFS{
			"run/udev/data/b8:16": {Data: []byte(strings.Join([]string{
				"E:DEVNAME=/dev/sdb",
				"E:DEVTYPE=disk",
				"E:ID_BUS=usb",
				"E:ID_VENDOR=aigo",
				"E:ID_MODEL=U391",
				"E:ID_SERIAL_SHORT=UDEV-SERIAL-001",
			}, "\n"))},
		},
		Journal: func(context.Context) ([]byte, error) {
			return []byte("Linux version fixture\n"), nil
		},
	}

	results, err := probe.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	var udevResult *usb.SourceResult
	for index := range results {
		if results[index].Name == "当前设备（udev）" {
			udevResult = &results[index]
			break
		}
	}
	if udevResult == nil || udevResult.Status != usb.StatusFound || len(udevResult.Records) != 1 {
		t.Fatalf("udev result = %#v; all results = %#v", udevResult, results)
	}
	record := udevResult.Records[0]
	if record.Vendor != "aigo" || record.Product != "U391" || record.Serial != "UDEV-SERIAL-001" || record.Detail != "/dev/sdb" || record.Cleanable {
		t.Fatalf("udev record = %#v", record)
	}
}

func TestUSBProbeFindsMountedDeviceOnlyWhenUdevIdentifiesItAsUSBStorage(t *testing.T) {
	probe := platform.USBProbe{
		Root: fstest.MapFS{
			"run/udev/data/b8:17": {Data: []byte(strings.Join([]string{
				"E:DEVNAME=/dev/sdb1",
				"E:DEVTYPE=disk",
				"E:ID_BUS=usb",
				"E:ID_VENDOR=aigo",
				"E:ID_MODEL=U391",
				"E:ID_SERIAL_SHORT=MOUNT-SERIAL-001",
			}, "\n"))},
			"proc/self/mountinfo": {Data: []byte(strings.Join([]string{
				"36 29 8:17 / /media/alice/U391 rw,nosuid,nodev - vfat /dev/sdb1 rw",
				"40 29 0:44 / /media/alice/not-usb rw - tmpfs tmpfs rw",
			}, "\n"))},
		},
		Journal: func(context.Context) ([]byte, error) {
			return []byte("Linux version fixture\n"), nil
		},
	}

	results, err := probe.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	mounts := sourceByName(t, results, "当前挂载（mountinfo）")
	if mounts.Status != usb.StatusFound || len(mounts.Records) != 1 {
		t.Fatalf("mount result = %#v", mounts)
	}
	record := mounts.Records[0]
	if record.Product != "U391" || record.Serial != "MOUNT-SERIAL-001" || record.Detail != "/dev/sdb1 → /media/alice/U391" || record.Cleanable {
		t.Fatalf("mount record = %#v", record)
	}
}

func TestUSBProbeReportsReadableUdevAndMountSourcesWithNoUSBAsNone(t *testing.T) {
	probe := platform.USBProbe{
		Root: fstest.MapFS{
			"run/udev/data":       {Mode: os.ModeDir | 0o755},
			"proc/self/mountinfo": {Data: []byte("40 29 0:44 / /media/alice/not-usb rw - tmpfs tmpfs rw\n")},
		},
		Journal: func(context.Context) ([]byte, error) {
			return []byte("Linux version fixture\n"), nil
		},
	}

	results, err := probe.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if sourceByName(t, results, "当前设备（udev）").Status != usb.StatusNone || sourceByName(t, results, "当前挂载（mountinfo）").Status != usb.StatusNone {
		t.Fatalf("results = %#v", results)
	}
}

func TestUSBProbeReportsMalformedMountInfoAsParseFailure(t *testing.T) {
	probe := platform.USBProbe{
		Root: fstest.MapFS{
			"run/udev/data":       {Mode: os.ModeDir | 0o755},
			"proc/self/mountinfo": {Data: []byte("not a mountinfo record\n")},
		},
		Journal: func(context.Context) ([]byte, error) {
			return []byte("Linux version fixture\n"), nil
		},
	}

	results, err := probe.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if sourceByName(t, results, "当前挂载（mountinfo）").Status != usb.StatusParseFailed {
		t.Fatalf("results = %#v", results)
	}
}

func TestUSBProbeFindsCurrentMTPPhoneWithoutTreatingSMBMountAsUSB(t *testing.T) {
	probe := platform.USBProbe{
		Root: fstest.MapFS{
			"run/user/1000/gvfs/mtp:host=USB_Phone_001":          {Mode: os.ModeDir | 0o755},
			"run/user/1000/gvfs/smb-share:server=files,share=it": {Mode: os.ModeDir | 0o755},
		},
		Journal: func(context.Context) ([]byte, error) {
			return []byte("Linux version fixture\n"), nil
		},
	}

	results, err := probe.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	gvfs := sourceByName(t, results, "当前用户设备（GVFS）")
	if gvfs.Status != usb.StatusFound || len(gvfs.Records) != 1 {
		t.Fatalf("GVFS result = %#v", gvfs)
	}
	if gvfs.Records[0].Product != "MTP移动设备" || !strings.Contains(gvfs.Records[0].Detail, "mtp:host=USB_Phone_001") || gvfs.Records[0].Cleanable {
		t.Fatalf("GVFS record = %#v", gvfs.Records[0])
	}
}

func TestUSBProbeReadsGVFSAsOwningDesktopUser(t *testing.T) {
	probe := platform.USBProbe{
		Root: fstest.MapFS{
			"run/user/1000": {Mode: os.ModeDir | 0o700},
		},
		GVFSEntries: func(_ context.Context, userID, path string) ([]string, error) {
			if userID != "1000" || path != "/run/user/1000/gvfs" {
				t.Fatalf("GVFS request user=%q path=%q", userID, path)
			}
			return []string{"mtp:host=USB_Phone_001", "smb-share:server=files,share=it"}, nil
		},
		Journal: func(context.Context) ([]byte, error) {
			return []byte("Linux version fixture\n"), nil
		},
	}

	results, err := probe.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	gvfs := sourceByName(t, results, "当前用户设备（GVFS）")
	if gvfs.Status != usb.StatusFound || len(gvfs.Records) != 1 || gvfs.Records[0].Product != "MTP移动设备" {
		t.Fatalf("GVFS result = %#v", gvfs)
	}
}

func TestUSBProbePreservesUsefulSanitizedHistoryEvidence(t *testing.T) {
	root := fstest.MapFS{
		"home/alice/.local/share/recently-used.xbel": {Data: []byte(`<xbel><bookmark href="file:///media/alice/WORK/private-report.docx" visited="2026-09-15T18:30:00Z"/></xbel>`)},
	}
	probe := platform.USBProbe{
		Root: root,
		Journal: func(context.Context) ([]byte, error) {
			return []byte("2026-09-15T18:00:00+08:00 kernel: usb-storage 1-1:1.0: USB Mass Storage device detected\n"), nil
		},
	}

	results, err := probe.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	journal := sourceByName(t, results, "内核日志（journal）")
	recent := sourceByName(t, results, "用户级最近文件记录")
	if len(journal.Records) != 1 || !strings.Contains(journal.Records[0].Evidence, "usb-storage 1-1:1.0") {
		t.Fatalf("journal evidence = %#v", journal.Records)
	}
	if len(recent.Records) != 1 {
		t.Fatalf("recent evidence = %#v", recent.Records)
	}
	evidence := recent.Records[0].Evidence
	for _, want := range []string{"用户=alice", "挂载点=/media/alice/WORK", "文件=***.docx", "最后访问=2026-09-15T18:30:00Z"} {
		if !strings.Contains(evidence, want) {
			t.Errorf("recent evidence missing %q: %s", want, evidence)
		}
	}
	if strings.Contains(evidence, "private-report") {
		t.Fatalf("recent evidence exposes file name: %s", evidence)
	}
}

func TestUSBProbeDoesNotClassifyInternalSCSIDisksAsUSBHistory(t *testing.T) {
	probe := platform.USBProbe{
		Root: fstest.MapFS{},
		Journal: func(context.Context) ([]byte, error) {
			return []byte(strings.Join([]string{
				"2026-09-15T12:57:18+0800 kernel: scsi 0:0:0:0: Direct-Access SKhynix InternalSSD A003 PQ: 0 ANSI: 6",
				"2026-09-15T12:57:18+0800 kernel: scsi 1:0:0:0: Direct-Access ATA InternalHDD CC38 PQ: 0 ANSI: 5",
				"2026-09-15T14:01:47+0800 kernel: scsi 4:0:0:0: Direct-Access USB SanDisk 3.2Gen1 1.00 PQ: 0 ANSI: 6",
				"2026-09-15T14:01:47+0800 kernel: sd 4:0:0:0: [sdf] Attached SCSI removable disk",
				"2026-09-15T15:00:00+0800 kernel: scsi 5:0:0:0: Direct-Access DockCase DSWC1M 1.00 PQ: 0 ANSI: 6",
				"2026-09-15T15:00:00+0800 kernel: sd 5:0:0:0: [sdg] Attached SCSI removable disk",
			}, "\n")), nil
		},
	}

	results, err := probe.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	journal := sourceByName(t, results, "内核日志（journal）")
	if len(journal.Records) != 4 {
		t.Fatalf("journal records = %#v, want only USB disk evidence", journal.Records)
	}
	for _, record := range journal.Records {
		if strings.Contains(record.Evidence, "InternalSSD") || strings.Contains(record.Evidence, "InternalHDD") {
			t.Fatalf("internal disk was classified as USB history: %s", record.Evidence)
		}
	}
}

func TestUSBProbeDoesNotClassifyUSBStorageDriverRegistrationAsDeviceHistory(t *testing.T) {
	probe := platform.USBProbe{
		Root: fstest.MapFS{},
		Journal: func(context.Context) ([]byte, error) {
			return []byte(strings.Join([]string{
				"2026-09-15T08:00:00+0800 kernel: usbcore: registered new interface driver usb-storage",
				"2026-09-15T14:01:47+0800 kernel: usb-storage 1-1:1.0: USB Mass Storage device detected",
			}, "\n")), nil
		},
	}

	results, err := probe.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	journal := sourceByName(t, results, "内核日志（journal）")
	if len(journal.Records) != 1 || !strings.Contains(journal.Records[0].Evidence, "USB Mass Storage device detected") {
		t.Fatalf("journal records = %#v, want only the actual device event", journal.Records)
	}
}

func TestUSBProbeExcludesItsOwnGeneratedReportsFromRecentHistory(t *testing.T) {
	probe := platform.USBProbe{
		Root: fstest.MapFS{
			"home/alice/.local/share/recently-used.xbel": {Data: []byte(`<xbel>
  <bookmark href="file:///media/USB/kylin-report_unknown_AA-BB_20260915-204947-600.html" visited="2026-09-15T20:49:50Z"/>
  <bookmark href="file:///media/USB/kylin-cleanup-report_unknown_AA-BB_20260915-204947-600.json" visited="2026-09-15T20:49:51Z"/>
  <bookmark href="file:///media/USB/user-document.pdf" visited="2026-09-15T20:40:00Z"/>
</xbel>`)},
		},
		Journal: func(context.Context) ([]byte, error) {
			return []byte("Linux version fixture\n"), nil
		},
	}

	results, err := probe.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	recent := sourceByName(t, results, "用户级最近文件记录")
	if len(recent.Records) != 1 || !strings.Contains(recent.Records[0].Evidence, "***.pdf") {
		t.Fatalf("recent records = %#v, want only user document", recent.Records)
	}
}

func TestUSBProbeUsesMountInfoForRecentFileMountPoint(t *testing.T) {
	probe := platform.USBProbe{
		Root: fstest.MapFS{
			"home/test/.local/share/recently-used.xbel": {Data: []byte(`<xbel><bookmark href="file:///media/edpedisk1/tools/private.pdf" visited="2026-09-15T20:40:00Z"/></xbel>`)},
			"proc/self/mountinfo":                       {Data: []byte("36 29 8:17 / /media/edpedisk1 rw,nosuid,nodev - vfat /dev/sdb1 rw\n")},
		},
		Journal: func(context.Context) ([]byte, error) {
			return []byte("Linux version fixture\n"), nil
		},
	}

	results, err := probe.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	recent := sourceByName(t, results, "用户级最近文件记录")
	if len(recent.Records) != 1 || !strings.Contains(recent.Records[0].Evidence, "挂载点=/media/edpedisk1；") {
		t.Fatalf("recent evidence = %#v", recent.Records)
	}
}

func TestUSBProbeLabelsInvalidRecentFileTimeAsUnknown(t *testing.T) {
	probe := platform.USBProbe{
		Root: fstest.MapFS{
			"home/test/.local/share/recently-used.xbel": {Data: []byte(`<xbel><bookmark href="file:///media/test/USB/private.pdf" visited="1969-12-31T23:59:59Z"/></xbel>`)},
		},
		Journal: func(context.Context) ([]byte, error) {
			return []byte("Linux version fixture\n"), nil
		},
	}

	results, err := probe.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	recent := sourceByName(t, results, "用户级最近文件记录")
	if len(recent.Records) != 1 || !strings.Contains(recent.Records[0].Evidence, "最后访问=时间未知") || strings.Contains(recent.Records[0].Evidence, "1969-") {
		t.Fatalf("recent evidence = %#v", recent.Records)
	}
}
