package firewall_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/core"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/firewall"
)

type fakeIPTables struct {
	saveOutputs []string
	commands    [][]string
	failRun     bool
	failAt      int
}

func (f *fakeIPTables) Save(context.Context) (string, error) {
	result := f.saveOutputs[0]
	f.saveOutputs = f.saveOutputs[1:]
	return result, nil
}

func (f *fakeIPTables) Run(_ context.Context, args []string) error {
	f.commands = append(f.commands, append([]string(nil), args...))
	if f.failRun && len(f.commands)-1 == f.failAt {
		return errors.New("simulated iptables failure")
	}
	return nil
}

func TestRepairAppliesPlanAndVerifiesResult(t *testing.T) {
	backend := &fakeIPTables{saveOutputs: []string{
		"-P INPUT ACCEPT\n-A INPUT -j CEMS_COMMON_INPUT",
		firewall.ExpectedSaveFixture(),
	}}
	remediator := firewall.NewRemediator(backend)

	checks, actions, err := remediator.Evaluate(context.Background(), core.ModeRepair)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(backend.commands) != 12 {
		t.Fatalf("executed commands = %d, want 12", len(backend.commands))
	}
	if len(actions) != 12 || len(checks) != 1 || checks[0].Conclusion != core.ConclusionPass {
		t.Fatalf("checks=%#v actions=%#v", checks, actions)
	}
	for _, command := range backend.commands {
		joined := strings.Join(command, " ")
		if strings.Contains(joined, "CEMS_") || strings.Contains(joined, "KSC_") {
			t.Fatalf("modified vendor chain: %s", joined)
		}
	}
}

func TestRepairRollsBackOnlySuccessfulManagedCommandsOnFailure(t *testing.T) {
	backend := &fakeIPTables{
		saveOutputs: []string{"-P INPUT ACCEPT\n-A INPUT -j CEMS_COMMON_INPUT"},
		failRun:     true,
		failAt:      1,
	}
	remediator := firewall.NewRemediator(backend)

	_, actions, err := remediator.Evaluate(context.Background(), core.ModeRepair)
	if err == nil {
		t.Fatal("Evaluate() error = nil, want repair failure")
	}
	if len(backend.commands) != 3 {
		t.Fatalf("commands = %#v", backend.commands)
	}
	if got := strings.Join(backend.commands[2], " "); got != "-X SEC_REMEDIATOR_INPUT" {
		t.Fatalf("rollback command = %q", got)
	}
	if len(actions) != 1 || actions[0].Status != "已回滚" {
		t.Fatalf("actions = %#v", actions)
	}
	for _, command := range backend.commands {
		joined := strings.Join(command, " ")
		if strings.Contains(joined, "CEMS_") || strings.Contains(joined, "KSC_") {
			t.Fatalf("modified vendor chain: %s", joined)
		}
	}
}

func TestRepairReportsSecurityPolicyOverrideWithoutRepeatedlyFightingIt(t *testing.T) {
	overridden := "-P INPUT ACCEPT\n-A INPUT -j CEMS_COMMON_INPUT"
	backend := &fakeIPTables{saveOutputs: []string{overridden, overridden}}
	remediator := firewall.NewRemediator(backend)

	checks, actions, err := remediator.Evaluate(context.Background(), core.ModeRepair)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(checks) != 1 || checks[0].Conclusion != core.ConclusionFail || !strings.Contains(checks[0].Actual, "安全策略覆盖") {
		t.Fatalf("checks = %#v", checks)
	}
	if len(backend.commands) != 12 {
		t.Fatalf("commands = %d, want one repair attempt of 12 commands", len(backend.commands))
	}
	for _, action := range actions {
		if action.Status != "被安全策略覆盖" {
			t.Fatalf("action = %#v", action)
		}
	}
}
