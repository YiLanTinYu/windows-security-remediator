package wireless_test

import (
	"context"
	"errors"
	"testing"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/core"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/wireless"
)

type fakeBackend struct {
	states       []wireless.State
	backedUp     []string
	deleted      []string
	radioChanges []bool
	restored     []string
	failDelete   string
}

func (f *fakeBackend) Backup(_ context.Context, profile wireless.Profile) (wireless.Backup, error) {
	f.backedUp = append(f.backedUp, profile.UUID)
	return wireless.Backup{Profile: profile}, nil
}

func (f *fakeBackend) Delete(_ context.Context, profile wireless.Profile) error {
	f.deleted = append(f.deleted, profile.UUID)
	if profile.UUID == f.failDelete {
		return errors.New("simulated delete failure")
	}
	return nil
}

func TestRepairRestoresEarlierWirelessProfilesWhenLaterDeleteFails(t *testing.T) {
	backend := &fakeBackend{
		states: []wireless.State{{Profiles: []wireless.Profile{
			{UUID: "first", Name: "First Wi-Fi", Kind: wireless.KindWireless},
			{UUID: "second", Name: "Second Wi-Fi", Kind: wireless.KindWireless},
		}}},
		failDelete: "second",
	}
	remediator := wireless.NewRemediator(backend)

	_, actions, err := remediator.Evaluate(context.Background(), core.ModeRepair)
	if err == nil {
		t.Fatal("Evaluate() error = nil, want delete failure")
	}
	if len(backend.restored) != 1 || backend.restored[0] != "first" {
		t.Fatalf("restored = %#v", backend.restored)
	}
	if len(actions) != 1 || actions[0].Status != "已回滚" {
		t.Fatalf("actions = %#v", actions)
	}
}

func (f *fakeBackend) SetRadio(_ context.Context, enabled bool) error {
	f.radioChanges = append(f.radioChanges, enabled)
	return nil
}

func (f *fakeBackend) Restore(_ context.Context, backup wireless.Backup) error {
	f.restored = append(f.restored, backup.Profile.UUID)
	return nil
}

func (f *fakeBackend) Snapshot(context.Context) (wireless.State, error) {
	state := f.states[0]
	f.states = f.states[1:]
	return state, nil
}

func TestRepairKeepsCurrentWirelessConnectionAndDeletesOnlyInactiveWirelessHistory(t *testing.T) {
	before := wireless.State{
		RadioEnabled: true,
		Devices:      []wireless.Device{{Name: "wlp2s0", Kind: wireless.KindWireless, Enabled: true}},
		Profiles: []wireless.Profile{
			{UUID: "current", Name: "Current Wi-Fi", Kind: wireless.KindWireless, Active: true},
			{UUID: "old", Name: "Old hotspot", Kind: wireless.KindWireless},
			{UUID: "wired", Name: "Office LAN", Kind: wireless.KindWired},
			{UUID: "unknown", Name: "Unknown profile", Kind: wireless.KindUnknown},
		},
	}
	after := before
	after.Profiles = []wireless.Profile{before.Profiles[0], before.Profiles[2], before.Profiles[3]}
	backend := &fakeBackend{states: []wireless.State{before, after}}
	remediator := wireless.NewRemediator(backend)

	checks, actions, err := remediator.Evaluate(context.Background(), core.ModeRepair)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(backend.deleted) != 1 || backend.deleted[0] != "old" {
		t.Fatalf("deleted = %#v", backend.deleted)
	}
	if len(backend.radioChanges) != 0 {
		t.Fatalf("radio changes = %#v", backend.radioChanges)
	}
	if len(actions) != 2 || actions[1].Status != "当前连接，未清理" {
		t.Fatalf("actions = %#v", actions)
	}
	if checks[0].Conclusion != core.ConclusionReview || checks[1].Conclusion != core.ConclusionReview {
		t.Fatalf("checks = %#v", checks)
	}
}

func TestRepairDeletesInactiveWirelessHistoryAndTurnsOffRadio(t *testing.T) {
	before := wireless.State{
		RadioEnabled: true,
		Devices:      []wireless.Device{{Name: "wlp2s0", Kind: wireless.KindWireless, Enabled: true}},
		Profiles:     []wireless.Profile{{UUID: "old", Name: "Old Wi-Fi", Kind: wireless.KindWireless}},
	}
	after := wireless.State{
		RadioEnabled: false,
		Devices:      []wireless.Device{{Name: "wlp2s0", Kind: wireless.KindWireless, Enabled: false}},
	}
	backend := &fakeBackend{states: []wireless.State{before, after}}
	remediator := wireless.NewRemediator(backend)

	checks, actions, err := remediator.Evaluate(context.Background(), core.ModeRepair)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(backend.backedUp) != 1 || len(backend.deleted) != 1 || len(backend.radioChanges) != 1 || backend.radioChanges[0] {
		t.Fatalf("backup=%#v delete=%#v radio=%#v", backend.backedUp, backend.deleted, backend.radioChanges)
	}
	if len(actions) != 2 || actions[0].Status != "已清理" || actions[1].Status != "已关闭" {
		t.Fatalf("actions = %#v", actions)
	}
	if checks[0].Conclusion != core.ConclusionPass || checks[1].Conclusion != core.ConclusionPass {
		t.Fatalf("checks = %#v", checks)
	}
}

func TestAuditSeparatesWirelessWiredAndUnknownConnections(t *testing.T) {
	backend := &fakeBackend{states: []wireless.State{{
		RadioEnabled: true,
		Devices:      []wireless.Device{{Name: "wlp2s0", Kind: wireless.KindWireless, Enabled: true}},
		Profiles: []wireless.Profile{
			{UUID: "wifi-1", Name: "Phone hotspot", Kind: wireless.KindWireless},
			{UUID: "wired-1", Name: "Wired connection", Kind: wireless.KindWired},
			{UUID: "vpn-1", Name: "Business VPN", Kind: wireless.KindUnknown},
		},
	}}}
	remediator := wireless.NewRemediator(backend)

	checks, actions, err := remediator.Evaluate(context.Background(), core.ModeAudit)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(actions) != 0 {
		t.Fatalf("audit actions = %#v", actions)
	}
	want := []core.Conclusion{core.ConclusionFail, core.ConclusionFail, core.ConclusionReview}
	if len(checks) != len(want) {
		t.Fatalf("checks = %#v", checks)
	}
	for index := range want {
		if checks[index].Conclusion != want[index] {
			t.Fatalf("check %d = %#v", index, checks[index])
		}
	}
	if checks[1].Actual != "发现1个无线/热点配置：Phone hotspot；有线配置1个（未处理）" {
		t.Fatalf("wireless profile result = %q", checks[1].Actual)
	}
	if checks[2].Actual != "发现1个类型不明配置：Business VPN" {
		t.Fatalf("unknown profile result = %q", checks[2].Actual)
	}
}
