package usb_test

import (
	"context"
	"strings"
	"testing"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/core"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/usb"
)

type fakeBackend struct {
	results []usb.SourceResult
	err     error
	cleaned []usb.Record
}

func (f fakeBackend) Scan(context.Context) ([]usb.SourceResult, error) { return f.results, f.err }

func (f *fakeBackend) CleanSafe(_ context.Context, records []usb.Record) error {
	f.cleaned = append(f.cleaned, records...)
	return nil
}

func TestCleanKeepsReadOnlyUSBSystemEvidence(t *testing.T) {
	backend := &fakeBackend{results: []usb.SourceResult{
		{
			Name: "当前设备（sysfs）", Status: usb.StatusFound,
			Records: []usb.Record{{Product: "Current USB disk"}},
		},
		{
			Name: "内核日志（journal）", Status: usb.StatusFound,
			Records: []usb.Record{{Product: "Historical USB event"}},
		},
		{
			Name: "当前设备（udev）", Status: usb.StatusFound,
			Records: []usb.Record{{Product: "Current udev USB disk"}},
		},
		{
			Name: "当前挂载（mountinfo）", Status: usb.StatusFound,
			Records: []usb.Record{{Product: "Current mounted USB disk"}},
		},
	}}
	auditor := usb.NewAuditor(backend)

	checks, actions, err := auditor.Evaluate(context.Background(), core.ModeClean)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(backend.cleaned) != 0 {
		t.Fatalf("cleaned read-only records = %#v", backend.cleaned)
	}
	if len(actions) != 1 || actions[0].Status != "无可安全单独清理项，系统证据已保留" {
		t.Fatalf("actions = %#v", actions)
	}
	if len(checks) != 5 || checks[4].Conclusion != core.ConclusionReview {
		t.Fatalf("checks = %#v", checks)
	}
}

func TestCleanDeletesOnlyExplicitlySafeUSBUserRecords(t *testing.T) {
	backend := &fakeBackend{results: []usb.SourceResult{{
		Name: "用户级最近挂载记录", Status: usb.StatusFound,
		Records: []usb.Record{
			{Product: "Safe recent mount", Locator: "user-cache:entry-1", Cleanable: true},
			{Product: "System journal evidence", Locator: "journal:event-1"},
		},
	}}}
	auditor := usb.NewAuditor(backend)

	_, actions, err := auditor.Evaluate(context.Background(), core.ModeClean)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(backend.cleaned) != 1 || backend.cleaned[0].Locator != "user-cache:entry-1" {
		t.Fatalf("cleaned = %#v", backend.cleaned)
	}
	if len(actions) != 1 || actions[0].Target != "Safe recent mount" || actions[0].Status != "已清理" {
		t.Fatalf("actions = %#v", actions)
	}
}

func TestAuditDistinguishesNoUSBHistoryFromUnavailableSources(t *testing.T) {
	tests := []struct {
		name       string
		status     usb.SourceStatus
		conclusion core.Conclusion
	}{
		{name: "confirmed none", status: usb.StatusNone, conclusion: core.ConclusionPass},
		{name: "permission denied", status: usb.StatusPermissionDenied, conclusion: core.ConclusionReview},
		{name: "source unavailable", status: usb.StatusUnavailable, conclusion: core.ConclusionReview},
		{name: "logs rotated", status: usb.StatusRotated, conclusion: core.ConclusionReview},
		{name: "parse failed", status: usb.StatusParseFailed, conclusion: core.ConclusionReview},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auditor := usb.NewAuditor(fakeBackend{results: []usb.SourceResult{{
				Name: "system journal", Status: test.status, Detail: "fixture",
			}}})
			checks, actions, err := auditor.Evaluate(context.Background(), core.ModeAudit)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if len(actions) != 0 || len(checks) != 2 {
				t.Fatalf("checks=%#v actions=%#v", checks, actions)
			}
			if checks[0].Conclusion != test.conclusion || checks[1].Conclusion != test.conclusion {
				t.Fatalf("checks = %#v", checks)
			}
		})
	}
}

func TestAuditReportsFoundUSBStorageWithoutExposingUnrelatedData(t *testing.T) {
	auditor := usb.NewAuditor(fakeBackend{results: []usb.SourceResult{{
		Name: "sysfs", Status: usb.StatusFound,
		Records: []usb.Record{{Vendor: "aigo", Product: "U391", Serial: "TEST-SERIAL"}},
	}}})

	checks, _, err := auditor.Evaluate(context.Background(), core.ModeAudit)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if checks[0].Conclusion != core.ConclusionReview || checks[1].Conclusion != core.ConclusionReview {
		t.Fatalf("checks = %#v", checks)
	}
	if checks[0].Actual != "找到1条：aigo U391（序列号 TEST-SERIAL）" {
		t.Fatalf("source actual = %q", checks[0].Actual)
	}
}

func TestAuditMarksConflictingCurrentUSBSourceResultsForReview(t *testing.T) {
	auditor := usb.NewAuditor(fakeBackend{results: []usb.SourceResult{
		{
			Name: "当前设备（sysfs）", Status: usb.StatusFound,
			Records: []usb.Record{{Product: "Current USB disk"}},
		},
		{Name: "当前设备（udev）", Status: usb.StatusNone, Detail: "udev数据库中未发现当前USB存储设备"},
		{Name: "当前挂载（mountinfo）", Status: usb.StatusNone, Detail: "未发现当前挂载的USB存储设备"},
	}})

	checks, _, err := auditor.Evaluate(context.Background(), core.ModeAudit)
	if err != nil {
		t.Fatal(err)
	}
	if checks[1].Conclusion != core.ConclusionReview || !strings.Contains(checks[1].Actual, "与sysfs") {
		t.Fatalf("udev check = %#v, want conflicting source marked for review", checks[1])
	}
	if checks[2].Conclusion != core.ConclusionReview || !strings.Contains(checks[2].Actual, "无法确认当前USB存储设备是否已挂载") {
		t.Fatalf("mountinfo check = %#v, want unverified mount state marked for review", checks[2])
	}
}

func TestAuditKeepsUnmountedUSBAsConfirmedNoneWhenUdevIdentifiesDevice(t *testing.T) {
	auditor := usb.NewAuditor(fakeBackend{results: []usb.SourceResult{
		{
			Name: "当前设备（sysfs）", Status: usb.StatusFound,
			Records: []usb.Record{{Product: "Current USB disk"}},
		},
		{
			Name: "当前设备（udev）", Status: usb.StatusFound,
			Records: []usb.Record{{Product: "Current USB disk", Detail: "/dev/sdb"}},
		},
		{Name: "当前挂载（mountinfo）", Status: usb.StatusNone, Detail: "未发现当前挂载的USB存储设备"},
	}})

	checks, _, err := auditor.Evaluate(context.Background(), core.ModeAudit)
	if err != nil {
		t.Fatal(err)
	}
	if checks[2].Conclusion != core.ConclusionPass || !strings.Contains(checks[2].Actual, "确定无记录") {
		t.Fatalf("mountinfo check = %#v, want a known but unmounted USB device to remain confirmed none", checks[2])
	}
}

func TestAuditKeepsUnmountedUSBAsConfirmedNoneWhenSysfsBlockDeviceIdentifiesDevice(t *testing.T) {
	auditor := usb.NewAuditor(fakeBackend{results: []usb.SourceResult{
		{
			Name: "当前设备（sysfs）", Status: usb.StatusFound,
			Records: []usb.Record{{Product: "Current USB disk"}},
		},
		{
			Name: "当前块设备（sysfs）", Status: usb.StatusFound,
			Records: []usb.Record{{Product: "Current USB disk", Detail: "/dev/sdb", Locator: "8:16"}},
		},
		{Name: "当前设备（udev）", Status: usb.StatusNone, Detail: "udev数据库中未发现当前USB存储设备"},
		{Name: "当前挂载（mountinfo）", Status: usb.StatusNone, Detail: "未发现当前挂载的USB存储设备"},
	}})

	checks, _, err := auditor.Evaluate(context.Background(), core.ModeAudit)
	if err != nil {
		t.Fatal(err)
	}
	if checks[3].Conclusion != core.ConclusionPass || !strings.Contains(checks[3].Actual, "确定无记录") {
		t.Fatalf("mountinfo check = %#v, want a sysfs-identified but unmounted USB block device to remain confirmed none", checks[3])
	}
}

func TestAuditShowsSystemDeviceLocationButNotCleanableRecentFileURL(t *testing.T) {
	auditor := usb.NewAuditor(fakeBackend{results: []usb.SourceResult{
		{
			Name: "当前挂载（mountinfo）", Status: usb.StatusFound,
			Records: []usb.Record{{Product: "U391", Detail: "/dev/sdb1 → /media/alice/U391"}},
		},
		{
			Name: "用户级最近文件记录", Status: usb.StatusFound,
			Records: []usb.Record{{Product: "最近访问的USB文件", Detail: "file:///media/alice/U391/private.txt", Cleanable: true}},
		},
	}})

	checks, _, err := auditor.Evaluate(context.Background(), core.ModeAudit)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !strings.Contains(checks[0].Actual, "/dev/sdb1 → /media/alice/U391") {
		t.Fatalf("mount evidence missing: %q", checks[0].Actual)
	}
	if strings.Contains(checks[1].Actual, "private.txt") {
		t.Fatalf("recent file URL exposed: %q", checks[1].Actual)
	}
}

func TestAuditDoesNotPresentJournalAndRecentFileEvidenceAsDeviceCount(t *testing.T) {
	auditor := usb.NewAuditor(fakeBackend{results: []usb.SourceResult{
		{
			Name: "内核日志（journal）", Status: usb.StatusFound,
			Records: []usb.Record{{Product: "历史USB存储事件"}, {Product: "历史USB存储事件"}, {Product: "历史USB存储事件"}},
		},
		{
			Name: "用户级最近文件记录", Status: usb.StatusFound,
			Records: []usb.Record{{Product: "最近访问的USB文件"}, {Product: "最近访问的USB文件"}},
		},
	}})

	checks, _, err := auditor.Evaluate(context.Background(), core.ModeAudit)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if checks[0].Actual != "找到3条相关日志事件（不等于3台设备）" {
		t.Fatalf("journal actual = %q", checks[0].Actual)
	}
	if checks[1].Actual != "找到2条USB文件访问记录（不等于2台设备）" {
		t.Fatalf("recent actual = %q", checks[1].Actual)
	}
	if !strings.Contains(checks[2].Actual, "不同数据源可能指向同一设备，不按设备数量合计") || strings.Contains(checks[2].Actual, "共找到5条USB存储设备记录") {
		t.Fatalf("summary = %q", checks[2].Actual)
	}
}
