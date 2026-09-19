package main

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/core"
)

type capturingRunner struct {
	request core.Request
}

func (r *capturingRunner) Run(_ context.Context, request core.Request) (core.Result, error) {
	r.request = request
	return core.Result{Identity: core.Identity{IP: "192.0.2.10", MAC: "02-00-00-00-00-10"}}, nil
}

func TestInteractiveOnsiteRunRepairsOnlyAfterYesConfirmation(t *testing.T) {
	dir := t.TempDir()
	runner := &capturingRunner{}
	var output bytes.Buffer
	now := func() time.Time { return time.Date(2026, 9, 13, 20, 0, 0, 0, time.Local) }

	exitCode := runOnsite(context.Background(), []string{"--output", dir}, strings.NewReader("yes\n"), &output, runner, now)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	if runner.request.Mode != core.ModeRepair {
		t.Fatalf("mode = %q, want repair", runner.request.Mode)
	}
	if !strings.Contains(output.String(), "输入 yes") || !strings.Contains(output.String(), filepath.Clean(dir)) {
		t.Fatalf("console output = %q", output.String())
	}
}

func TestInteractiveOnsiteRunFallsBackToAuditWhenRepairIsNotConfirmed(t *testing.T) {
	dir := t.TempDir()
	runner := &capturingRunner{}

	exitCode := runOnsite(context.Background(), []string{"--output", dir}, strings.NewReader("no\n"), io.Discard, runner, time.Now)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	if runner.request.Mode != core.ModeAudit {
		t.Fatalf("mode = %q, want audit", runner.request.Mode)
	}
}

func TestExplicitOnsiteModeDoesNotPrompt(t *testing.T) {
	dir := t.TempDir()
	runner := &capturingRunner{}
	var output bytes.Buffer

	exitCode := runOnsite(context.Background(), []string{"--audit", "--output", dir}, strings.NewReader("yes\n"), &output, runner, time.Now)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	if runner.request.Mode != core.ModeAudit {
		t.Fatalf("mode = %q, want audit", runner.request.Mode)
	}
	if strings.Contains(output.String(), "输入 yes") {
		t.Fatalf("explicit mode unexpectedly prompted: %q", output.String())
	}
}
