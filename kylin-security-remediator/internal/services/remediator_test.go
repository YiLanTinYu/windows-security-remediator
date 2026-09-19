package services_test

import (
	"context"
	"errors"
	"testing"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/core"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/services"
)

type fakeServices struct {
	states   map[string]services.State
	disabled []string
	restored []string
	failOn   string
	noChange bool
}

func (f *fakeServices) State(_ context.Context, name string) (services.State, error) {
	state, ok := f.states[name]
	if !ok {
		return services.State{}, nil
	}
	return state, nil
}

func (f *fakeServices) DisableNow(_ context.Context, name string) error {
	f.disabled = append(f.disabled, name)
	if name == f.failOn {
		return errors.New("simulated failure")
	}
	if !f.noChange {
		f.states[name] = services.State{Exists: true, Active: false, Enabled: false}
	}
	return nil
}

func (f *fakeServices) Restore(_ context.Context, name string, state services.State) error {
	f.restored = append(f.restored, name)
	f.states[name] = state
	return nil
}

func TestRepairStopsAndDisablesExistingServerServices(t *testing.T) {
	backend := &fakeServices{states: map[string]services.State{
		"sshd.service": {Exists: true, Active: true, Enabled: true},
		"smbd.service": {Exists: true, Active: false, Enabled: true},
		"xrdp.service": {Exists: true, Active: false, Enabled: false},
	}}
	remediator := services.NewRemediator(backend)

	checks, actions, err := remediator.Evaluate(context.Background(), core.ModeRepair)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(backend.disabled) != 2 || backend.disabled[0] != "sshd.service" || backend.disabled[1] != "smbd.service" {
		t.Fatalf("disabled = %#v", backend.disabled)
	}
	if len(actions) != 2 {
		t.Fatalf("actions = %#v", actions)
	}
	for _, check := range checks {
		if check.Conclusion != core.ConclusionPass && check.Conclusion != core.ConclusionNA {
			t.Fatalf("unexpected check = %#v", check)
		}
	}
}

func TestRepairRollsBackChangedServicesWhenLaterServiceFails(t *testing.T) {
	backend := &fakeServices{states: map[string]services.State{
		"sshd.service": {Exists: true, Active: true, Enabled: true},
		"ssh.service":  {Exists: true, Active: false, Enabled: true},
	}, failOn: "ssh.service"}
	remediator := services.NewRemediator(backend)

	_, _, err := remediator.Evaluate(context.Background(), core.ModeRepair)
	if err == nil {
		t.Fatal("Evaluate() error = nil, want repair failure")
	}
	if len(backend.restored) != 2 || backend.restored[0] != "ssh.service" || backend.restored[1] != "sshd.service" {
		t.Fatalf("restored = %#v", backend.restored)
	}
	if got := backend.states["sshd.service"]; !got.Active || !got.Enabled {
		t.Fatalf("sshd state after rollback = %#v", got)
	}
}

func TestRepairProcessesSystemdAliasesOnlyOnce(t *testing.T) {
	backend := &fakeServices{states: map[string]services.State{
		"sshd.service": {Exists: true, Active: true, Enabled: true, Canonical: "ssh.service"},
		"ssh.service":  {Exists: true, Active: true, Enabled: true, Canonical: "ssh.service"},
	}}
	remediator := services.NewRemediator(backend)

	_, _, err := remediator.Evaluate(context.Background(), core.ModeRepair)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(backend.disabled) != 1 || backend.disabled[0] != "sshd.service" {
		t.Fatalf("disabled aliases = %#v", backend.disabled)
	}
}

func TestRepairRollsBackWhenVerificationDoesNotConfirm(t *testing.T) {
	backend := &fakeServices{states: map[string]services.State{
		"sshd.service": {Exists: true, Active: true, Enabled: true},
	}, noChange: true}
	remediator := services.NewRemediator(backend)

	_, actions, err := remediator.Evaluate(context.Background(), core.ModeRepair)
	if err == nil {
		t.Fatal("Evaluate() error = nil, want verification failure")
	}
	if len(backend.restored) != 1 || backend.restored[0] != "sshd.service" {
		t.Fatalf("restored = %#v", backend.restored)
	}
	if len(actions) != 1 || actions[0].Status != "已回滚" {
		t.Fatalf("actions = %#v", actions)
	}
}
