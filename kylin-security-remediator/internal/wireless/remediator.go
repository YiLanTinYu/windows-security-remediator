package wireless

import (
	"context"
	"fmt"
	"strings"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/core"
)

type Kind string

const (
	KindWireless Kind = "wireless"
	KindWired    Kind = "wired"
	KindUnknown  Kind = "unknown"
)

type Device struct {
	Name    string
	Kind    Kind
	Enabled bool
}

type Profile struct {
	UUID   string
	Name   string
	Kind   Kind
	Active bool
}

type State struct {
	RadioEnabled bool
	Devices      []Device
	Profiles     []Profile
}

type Backup struct {
	Profile Profile
	Path    string
	Data    []byte
	Mode    uint32
}

type Backend interface {
	Snapshot(context.Context) (State, error)
	Backup(context.Context, Profile) (Backup, error)
	Delete(context.Context, Profile) error
	SetRadio(context.Context, bool) error
	Restore(context.Context, Backup) error
}

type Remediator struct{ backend Backend }

func NewRemediator(backend Backend) *Remediator { return &Remediator{backend: backend} }

func (r *Remediator) Evaluate(ctx context.Context, mode core.Mode) ([]core.Check, []core.Action, error) {
	state, err := r.backend.Snapshot(ctx)
	if err != nil {
		return []core.Check{{
			Category: "网络/无线", Item: "NetworkManager数据源", Expected: "能够正常读取",
			Actual: "数据源不可用：" + err.Error(), Conclusion: core.ConclusionReview,
			Details: []core.Detail{{Name: "数据来源", Value: "NetworkManager / nmcli"}, {Name: "读取错误", Value: err.Error()}},
		}}, nil, nil
	}

	if mode == core.ModeAudit {
		return buildChecks(state, false), nil, nil
	}

	var backups []Backup
	var actions []core.Action
	var activeWireless []Profile
	for _, profile := range state.Profiles {
		if profile.Kind != KindWireless {
			continue
		}
		if profile.Active {
			activeWireless = append(activeWireless, profile)
			continue
		}
		backup, backupErr := r.backend.Backup(ctx, profile)
		if backupErr != nil {
			return buildChecks(state, false), actions, fmt.Errorf("备份无线配置 %s: %w", profile.Name, backupErr)
		}
		if deleteErr := r.backend.Delete(ctx, profile); deleteErr != nil {
			rollbackErr := r.rollback(ctx, backups)
			markRolledBack(actions)
			if rollbackErr != nil {
				return buildChecks(state, false), actions, fmt.Errorf("删除无线配置 %s: %w；回滚失败: %v", profile.Name, deleteErr, rollbackErr)
			}
			return buildChecks(state, false), actions, fmt.Errorf("删除无线配置 %s: %w；已回滚", profile.Name, deleteErr)
		}
		backups = append(backups, backup)
		actions = append(actions, core.Action{Kind: "wireless-profile", Target: profile.Name, Status: "已清理"})
	}
	for _, profile := range activeWireless {
		actions = append(actions, core.Action{Kind: "wireless-profile", Target: profile.Name, Status: "当前连接，未清理"})
	}
	radioChanged := false
	if len(activeWireless) == 0 && state.RadioEnabled {
		if radioErr := r.backend.SetRadio(ctx, false); radioErr != nil {
			rollbackErr := r.rollback(ctx, backups)
			markRolledBack(actions)
			if rollbackErr != nil {
				return buildChecks(state, false), actions, fmt.Errorf("关闭无线功能: %w；回滚失败: %v", radioErr, rollbackErr)
			}
			return buildChecks(state, false), actions, fmt.Errorf("关闭无线功能: %w；已回滚", radioErr)
		}
		radioChanged = true
		actions = append(actions, core.Action{Kind: "wireless-radio", Target: "Wi-Fi", Status: "已关闭"})
	}
	after, snapshotErr := r.backend.Snapshot(ctx)
	if snapshotErr != nil {
		rollbackErr := r.rollbackRepair(ctx, backups, radioChanged, state.RadioEnabled)
		markRolledBack(actions)
		if rollbackErr != nil {
			return nil, actions, fmt.Errorf("复检无线配置: %w；回滚失败: %v", snapshotErr, rollbackErr)
		}
		return nil, actions, fmt.Errorf("复检无线配置: %w；已回滚", snapshotErr)
	}
	return buildChecks(after, len(activeWireless) > 0), actions, nil
}

func buildChecks(state State, preservedActive bool) []core.Check {
	var wirelessDevices []string
	var wirelessProfiles []string
	var unknownProfiles []string
	wiredProfiles := 0
	for _, device := range state.Devices {
		if device.Kind == KindWireless {
			wirelessDevices = append(wirelessDevices, device.Name)
		}
	}
	for _, profile := range state.Profiles {
		switch profile.Kind {
		case KindWireless:
			wirelessProfiles = append(wirelessProfiles, profile.Name)
		case KindWired:
			wiredProfiles++
		default:
			unknownProfiles = append(unknownProfiles, profile.Name)
		}
	}

	checks := []core.Check{wirelessDeviceCheck(state, wirelessDevices)}
	profileCheck := core.Check{
		Category: "网络/无线", Item: "无线网络和手机热点历史", Expected: "无线/热点配置为0；有线配置不处理",
		Actual:     fmt.Sprintf("发现%d个无线/热点配置：%s；有线配置%d个（未处理）", len(wirelessProfiles), displayNames(wirelessProfiles), wiredProfiles),
		Conclusion: core.ConclusionPass,
		Details:    profileDetails(state.Profiles, KindWireless, "NetworkManager连接配置"),
	}
	if len(wirelessProfiles) > 0 {
		profileCheck.Conclusion = core.ConclusionFail
	}
	if preservedActive && len(wirelessProfiles) > 0 {
		profileCheck.Actual += "；当前无线连接为避免断网已保留"
		profileCheck.Conclusion = core.ConclusionReview
	}
	checks = append(checks, profileCheck)
	unknownCheck := core.Check{
		Category: "网络/无线", Item: "类型不明网络配置", Expected: "列出供人工确认，不自动处理",
		Actual:     fmt.Sprintf("发现%d个类型不明配置：%s", len(unknownProfiles), displayNames(unknownProfiles)),
		Conclusion: core.ConclusionPass,
		Details:    profileDetails(state.Profiles, KindUnknown, "NetworkManager连接配置"),
	}
	if len(unknownProfiles) > 0 {
		unknownCheck.Conclusion = core.ConclusionReview
	}
	if preservedActive && checks[0].Conclusion == core.ConclusionFail {
		checks[0].Actual += "；当前无线连接为避免断网未关闭"
		checks[0].Conclusion = core.ConclusionReview
	}
	checks = append(checks, unknownCheck)
	return checks
}

func (r *Remediator) rollback(ctx context.Context, backups []Backup) error {
	for index := len(backups) - 1; index >= 0; index-- {
		if err := r.backend.Restore(ctx, backups[index]); err != nil {
			return err
		}
	}
	return nil
}

func (r *Remediator) rollbackRepair(ctx context.Context, backups []Backup, radioChanged, radioWasEnabled bool) error {
	if radioChanged {
		if err := r.backend.SetRadio(ctx, radioWasEnabled); err != nil {
			return err
		}
	}
	return r.rollback(ctx, backups)
}

func markRolledBack(actions []core.Action) {
	for index := range actions {
		if actions[index].Status != "当前连接，未清理" {
			actions[index].Status = "已回滚"
		}
	}
}

func wirelessDeviceCheck(state State, names []string) core.Check {
	check := core.Check{
		Category: "网络/无线", Item: "无线网卡", Expected: "全部禁用",
		Actual: "未识别到无线网卡", Conclusion: core.ConclusionNA,
		Details: []core.Detail{{Name: "数据来源", Value: "NetworkManager设备状态"}, {Name: "无线射频", Value: enabledText(state.RadioEnabled)}},
	}
	if len(names) == 0 {
		return check
	}
	check.Actual = fmt.Sprintf("无线功能启用=%t；网卡：%s", state.RadioEnabled, strings.Join(names, "、"))
	for _, device := range state.Devices {
		if device.Kind == KindWireless {
			check.Details = append(check.Details, core.Detail{Name: "无线网卡 " + device.Name, Value: "设备状态=" + enabledText(device.Enabled)})
		}
	}
	check.Conclusion = core.ConclusionPass
	if state.RadioEnabled {
		check.Conclusion = core.ConclusionFail
		return check
	}
	for _, device := range state.Devices {
		if device.Kind == KindWireless && device.Enabled {
			check.Conclusion = core.ConclusionFail
			break
		}
	}
	return check
}

func profileDetails(profiles []Profile, kind Kind, source string) []core.Detail {
	details := []core.Detail{{Name: "数据来源", Value: source}}
	matched := 0
	for _, profile := range profiles {
		if profile.Kind != kind {
			continue
		}
		matched++
		state := "未连接"
		if profile.Active {
			state = "当前连接"
		}
		details = append(details, core.Detail{Name: fmt.Sprintf("配置%02d", matched), Value: profile.Name + "（" + state + "）"})
	}
	if matched == 0 {
		details = append(details, core.Detail{Name: "配置记录", Value: "0个"})
	}
	return details
}

func enabledText(enabled bool) string {
	if enabled {
		return "启用"
	}
	return "禁用"
}

func displayNames(names []string) string {
	if len(names) == 0 {
		return "无"
	}
	return strings.Join(names, "、")
}
