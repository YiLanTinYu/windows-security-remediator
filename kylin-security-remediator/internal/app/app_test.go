package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/app"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/core"
)

type fixedRunner struct{ result core.Result }

func (r fixedRunner) Run(context.Context, core.Request) (core.Result, error) { return r.result, nil }

type failingRunner struct{ result core.Result }

func (r failingRunner) Run(context.Context, core.Request) (core.Result, error) {
	return r.result, errors.New("simulated browser database lock")
}

type capturingUploader struct {
	localPaths  []string
	remoteNames []string
}

type failingUploader struct{ err error }

func (u failingUploader) UploadFile(context.Context, string, string) error { return u.err }

func TestUploadFailureKeepsReportsAndWritesLocalStatus(t *testing.T) {
	dir := t.TempDir()
	runner := fixedRunner{result: core.Result{Identity: core.Identity{
		IP: "192.0.2.60", MAC: "AA-00-BB-11-CC-22",
	}}}
	now := func() time.Time { return time.Date(2026, 9, 13, 12, 0, 0, 321000000, time.Local) }

	exitCode := app.RunWithUploader(context.Background(), []string{"--repair", "--output", dir}, runner, now, failingUploader{err: errors.New("server unavailable")})
	if exitCode != 3 {
		t.Fatalf("exit code = %d, want 3", exitCode)
	}
	base := filepath.Join(dir, "verification-report_192.0.2.60_AA-00-BB-11-CC-22_20260913-120000-321")
	for _, extension := range []string{".html", ".json"} {
		if _, err := os.Stat(base + extension); err != nil {
			t.Fatalf("local report was not preserved: %v", err)
		}
	}
	status, err := os.ReadFile(filepath.Join(dir, "upload-status_192.0.2.60_AA-00-BB-11-CC-22_20260913-120000-321.json"))
	if err != nil {
		t.Fatalf("missing upload status: %v", err)
	}
	if !strings.Contains(string(status), `"status": "failed"`) || !strings.Contains(string(status), "server unavailable") {
		t.Fatalf("unexpected upload status: %s", status)
	}
}

func (u *capturingUploader) UploadFile(_ context.Context, localPath, remoteName string) error {
	u.localPaths = append(u.localPaths, localPath)
	u.remoteNames = append(u.remoteNames, remoteName)
	data, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return errors.New("report file is empty")
	}
	return nil
}

func TestRunWithUploaderUploadsClosedHTMLAndJSONReports(t *testing.T) {
	dir := t.TempDir()
	uploader := &capturingUploader{}
	runner := fixedRunner{result: core.Result{Identity: core.Identity{
		IP: "192.0.2.50", MAC: "10-20-30-40-50-60",
	}}}
	now := func() time.Time { return time.Date(2026, 9, 13, 11, 30, 0, 123000000, time.Local) }

	exitCode := app.RunWithUploader(context.Background(), []string{"--repair", "--output", dir}, runner, now, uploader)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	if len(uploader.localPaths) != 2 || len(uploader.remoteNames) != 2 {
		t.Fatalf("uploads = %#v / %#v", uploader.localPaths, uploader.remoteNames)
	}
	if filepath.Ext(uploader.remoteNames[0]) != ".json" || filepath.Ext(uploader.remoteNames[1]) != ".html" {
		t.Fatalf("remote names = %#v", uploader.remoteNames)
	}
}

func TestOnsiteAndFTPProduceIdenticalBusinessReportsForSameResult(t *testing.T) {
	onsiteDir := t.TempDir()
	ftpDir := t.TempDir()
	runner := fixedRunner{result: core.Result{
		Identity:     core.Identity{IP: "192.0.2.70", MAC: "02-00-00-00-00-70"},
		BeforeChecks: []core.Check{{Category: "服务", Item: "SSH", Actual: "运行中", Conclusion: core.ConclusionFail}},
		AfterChecks:  []core.Check{{Category: "服务", Item: "SSH", Actual: "已停止", Conclusion: core.ConclusionPass}},
		Checks:       []core.Check{{Category: "服务", Item: "SSH", Actual: "已停止", Conclusion: core.ConclusionPass}},
		Actions:      []core.Action{{Kind: "service", Target: "ssh.service", Status: "成功"}},
	}}
	now := func() time.Time { return time.Date(2026, 9, 13, 20, 30, 0, 456000000, time.Local) }

	if code := app.Run(context.Background(), []string{"--repair", "--output", onsiteDir}, runner, now); code != 0 {
		t.Fatalf("onsite exit code = %d", code)
	}
	if code := app.RunWithUploader(context.Background(), []string{"--repair", "--output", ftpDir}, runner, now, &capturingUploader{}); code != 0 {
		t.Fatalf("FTP exit code = %d", code)
	}
	base := "verification-report_192.0.2.70_02-00-00-00-00-70_20260913-203000-456"
	for _, extension := range []string{".json", ".html"} {
		onsite, err := os.ReadFile(filepath.Join(onsiteDir, base+extension))
		if err != nil {
			t.Fatal(err)
		}
		ftp, err := os.ReadFile(filepath.Join(ftpDir, base+extension))
		if err != nil {
			t.Fatal(err)
		}
		if string(onsite) != string(ftp) {
			t.Fatalf("%s business reports differ", extension)
		}
	}
}

func TestFailureStillWritesPartialReportWithErrorReason(t *testing.T) {
	dir := t.TempDir()
	runner := failingRunner{result: core.Result{
		Identity: core.Identity{IP: "192.0.2.40", MAC: "00-11-22-33-44-55"},
		Checks: []core.Check{{
			Category: "浏览器登录", Item: "Chromium / user / Default",
			Actual: "发现1条保存密码记录", Conclusion: core.ConclusionFail,
		}},
	}}
	now := func() time.Time { return time.Date(2026, 9, 13, 10, 0, 0, 789000000, time.Local) }

	exitCode := app.Run(context.Background(), []string{"--clean", "--output", dir}, runner, now)
	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
	base := filepath.Join(dir, "kylin-cleanup-report_192.0.2.40_00-11-22-33-44-55_20260913-100000-789")
	for _, extension := range []string{".html", ".json"} {
		data, err := os.ReadFile(base + extension)
		if err != nil {
			t.Fatalf("missing failure report %s: %v", extension, err)
		}
		if !strings.Contains(string(data), "simulated browser database lock") {
			t.Fatalf("failure report %s missing error reason: %s", extension, data)
		}
	}
}

type capturingRunner struct {
	result  core.Result
	request core.Request
}

func (r *capturingRunner) Run(_ context.Context, request core.Request) (core.Result, error) {
	r.request = request
	return r.result, nil
}

func TestCleanUsesCleanModeAndCleanupReportName(t *testing.T) {
	dir := t.TempDir()
	runner := &capturingRunner{result: core.Result{Identity: core.Identity{
		IP: "192.0.2.30", MAC: "AA-BB-CC-DD-EE-FF",
	}}}
	now := func() time.Time { return time.Date(2026, 9, 13, 9, 15, 0, 456000000, time.Local) }

	exitCode := app.Run(context.Background(), []string{"--clean", "--output", dir}, runner, now)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	if runner.request.Mode != core.ModeClean {
		t.Fatalf("mode = %q, want %q", runner.request.Mode, core.ModeClean)
	}
	base := "kylin-cleanup-report_192.0.2.30_AA-BB-CC-DD-EE-FF_20260913-091500-456"
	for _, extension := range []string{".html", ".json"} {
		if _, err := os.Stat(filepath.Join(dir, base+extension)); err != nil {
			t.Errorf("missing %s report: %v", extension, err)
		}
	}
}

func TestAuditCreatesWindowsCompatibleHTMLAndJSONReports(t *testing.T) {
	dir := t.TempDir()
	runner := fixedRunner{result: core.Result{
		Identity: core.Identity{Hostname: "KYLIN-PC", IP: "192.0.2.20", MAC: "18-3D-2D-C6-47-7B"},
		Checks:   []core.Check{{Category: "防火墙", Item: "高危端口入站阻断规则", Actual: "仍需1项调整", Conclusion: core.ConclusionFail}},
	}}
	now := func() time.Time { return time.Date(2026, 9, 13, 8, 30, 45, 123000000, time.Local) }

	exitCode := app.Run(context.Background(), []string{"--audit", "--output", dir}, runner, now)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	base := "verification-report_192.0.2.20_18-3D-2D-C6-47-7B_20260913-083045-123"
	for _, extension := range []string{".html", ".json"} {
		if _, err := os.Stat(filepath.Join(dir, base+extension)); err != nil {
			t.Errorf("missing %s report: %v", extension, err)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, base+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Platform string       `json:"platform"`
		IP       string       `json:"ip"`
		MAC      string       `json:"mac"`
		Computer string       `json:"computer"`
		Finished string       `json:"finished"`
		Summary  []core.Check `json:"summary"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Platform != "Kylin" || payload.IP != "192.0.2.20" || payload.MAC != "18-3D-2D-C6-47-7B" || payload.Computer != "KYLIN-PC" {
		t.Fatalf("unexpected compatibility identity: %#v", payload)
	}
	if payload.Finished != "2026-09-13 08:30:45" || len(payload.Summary) != 1 || payload.Summary[0].Item != "高危端口入站阻断规则" {
		t.Fatalf("unexpected compatibility summary: %#v", payload)
	}
}
