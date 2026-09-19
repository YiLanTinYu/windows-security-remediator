package core_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/core"
)

type fixedIdentityProbe struct {
	identity core.Identity
}

type beforeAfterComponent struct{}

func (beforeAfterComponent) Evaluate(_ context.Context, mode core.Mode) ([]core.Check, []core.Action, error) {
	if mode == core.ModeAudit {
		return []core.Check{{Item: "SSH服务", Actual: "正在运行", Conclusion: core.ConclusionFail}}, nil, nil
	}
	return []core.Check{{Item: "SSH服务", Actual: "已停止、已禁用", Conclusion: core.ConclusionPass}}, []core.Action{{
		Kind: "service", Target: "ssh.service", Status: "已修复",
	}}, nil
}

func TestRepairKeepsBeforeAndAfterChecksInOneResult(t *testing.T) {
	engine := core.NewEngine(fixedIdentityProbe{}, beforeAfterComponent{})

	result, err := engine.Run(context.Background(), core.Request{Mode: core.ModeRepair})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.BeforeChecks) != 1 || result.BeforeChecks[0].Actual != "正在运行" {
		t.Fatalf("before checks = %#v", result.BeforeChecks)
	}
	if len(result.AfterChecks) != 1 || result.AfterChecks[0].Actual != "已停止、已禁用" {
		t.Fatalf("after checks = %#v", result.AfterChecks)
	}
	if len(result.Checks) != 1 || result.Checks[0].Actual != "已停止、已禁用" {
		t.Fatalf("final checks = %#v", result.Checks)
	}
	if len(result.Actions) != 1 || result.Actions[0].Target != "ssh.service" {
		t.Fatalf("actions = %#v", result.Actions)
	}
}

func (p fixedIdentityProbe) Identity(context.Context) (core.Identity, error) {
	return p.identity, nil
}

func TestAuditReturnsTerminalIdentityWithoutChangingSystem(t *testing.T) {
	want := core.Identity{
		Hostname: "kylin-test",
		OS:       "Kylin V10 SP1",
		Arch:     "amd64",
		IP:       "192.0.2.10",
		MAC:      "02-00-00-00-00-10",
	}
	engine := core.NewEngine(fixedIdentityProbe{identity: want})

	got, err := engine.Run(context.Background(), core.Request{Mode: core.ModeAudit})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !reflect.DeepEqual(got.Identity, want) {
		t.Fatalf("identity = %#v, want %#v", got.Identity, want)
	}
	if len(got.Actions) != 0 {
		t.Fatalf("audit actions = %#v, want none", got.Actions)
	}
	if got.Scope != core.RuntimeScope {
		t.Fatalf("scope = %q, want %q", got.Scope, core.RuntimeScope)
	}
}
