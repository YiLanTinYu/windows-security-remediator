package services

import (
	"context"
	"fmt"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/core"
)

type State struct {
	Exists    bool
	Active    bool
	Enabled   bool
	Canonical string
}

type Backend interface {
	State(context.Context, string) (State, error)
	DisableNow(context.Context, string) error
	Restore(context.Context, string, State) error
}

type target struct {
	Name     string
	Category string
}

type changedService struct {
	name  string
	state State
}

var targets = []target{
	{Name: "sshd.service", Category: "SSH远程登录"},
	{Name: "ssh.service", Category: "SSH远程登录"},
	{Name: "smbd.service", Category: "文件共享"},
	{Name: "nmbd.service", Category: "文件共享"},
	{Name: "samba.service", Category: "文件共享"},
	{Name: "xrdp.service", Category: "远程桌面"},
	{Name: "vncserver.service", Category: "远程桌面"},
	{Name: "vino-server.service", Category: "远程桌面"},
}

type Remediator struct{ backend Backend }

func NewRemediator(backend Backend) *Remediator { return &Remediator{backend: backend} }

func (r *Remediator) Evaluate(ctx context.Context, mode core.Mode) ([]core.Check, []core.Action, error) {
	var checks []core.Check
	var actions []core.Action
	var changed []changedService
	seen := make(map[string]bool)
	for _, item := range targets {
		state, err := r.backend.State(ctx, item.Name)
		if err != nil {
			return checks, actions, fmt.Errorf("读取服务 %s: %w", item.Name, err)
		}
		if !state.Exists {
			checks = append(checks, serviceCheck(item, state, core.ConclusionNA))
			continue
		}
		canonical := state.Canonical
		if canonical == "" {
			canonical = item.Name
		}
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		if mode != core.ModeAudit && (state.Active || state.Enabled) {
			changed = append(changed, changedService{name: item.Name, state: state})
			if err := r.backend.DisableNow(ctx, item.Name); err != nil {
				rollbackErr := r.rollback(ctx, changed)
				markRolledBack(actions)
				if rollbackErr != nil {
					return checks, actions, fmt.Errorf("停止并禁用服务 %s: %w；回滚失败: %v", item.Name, err, rollbackErr)
				}
				return checks, actions, fmt.Errorf("停止并禁用服务 %s: %w；已回滚", item.Name, err)
			}
			actions = append(actions, core.Action{Kind: "systemd", Target: item.Name, Status: "已停止并禁用"})
			state, err = r.backend.State(ctx, item.Name)
			if err != nil {
				rollbackErr := r.rollback(ctx, changed)
				markRolledBack(actions)
				if rollbackErr != nil {
					return checks, actions, fmt.Errorf("复检服务 %s: %w；回滚失败: %v", item.Name, err, rollbackErr)
				}
				return checks, actions, fmt.Errorf("复检服务 %s: %w；已回滚", item.Name, err)
			}
			if state.Active || state.Enabled {
				rollbackErr := r.rollback(ctx, changed)
				markRolledBack(actions)
				if rollbackErr != nil {
					return checks, actions, fmt.Errorf("服务 %s 修复后仍启用；回滚失败: %v", item.Name, rollbackErr)
				}
				return checks, actions, fmt.Errorf("服务 %s 修复后仍启用；已回滚", item.Name)
			}
		}
		conclusion := core.ConclusionPass
		if state.Active || state.Enabled {
			conclusion = core.ConclusionFail
		}
		checks = append(checks, serviceCheck(item, state, conclusion))
	}
	return checks, actions, nil
}

func markRolledBack(actions []core.Action) {
	for index := range actions {
		actions[index].Status = "已回滚"
	}
}

func (r *Remediator) rollback(ctx context.Context, changed []changedService) error {
	for index := len(changed) - 1; index >= 0; index-- {
		if err := r.backend.Restore(ctx, changed[index].name, changed[index].state); err != nil {
			return err
		}
	}
	return nil
}

func serviceCheck(item target, state State, conclusion core.Conclusion) core.Check {
	actual := "未安装"
	details := []core.Detail{{Name: "数据来源", Value: "systemctl show / systemctl is-enabled"}, {Name: "服务单元", Value: item.Name}}
	if state.Exists {
		active := "已停止"
		if state.Active {
			active = "正在运行"
		}
		enabled := "已禁用"
		if state.Enabled {
			enabled = "已启用"
		}
		actual = fmt.Sprintf("运行状态=%s，开机状态=%s", active, enabled)
		details = append(details, core.Detail{Name: "安装状态", Value: "已安装"}, core.Detail{Name: "运行状态", Value: active}, core.Detail{Name: "开机状态", Value: enabled})
		if state.Canonical != "" && state.Canonical != item.Name {
			details = append(details, core.Detail{Name: "规范服务名", Value: state.Canonical})
		}
	} else {
		details = append(details, core.Detail{Name: "安装状态", Value: "未安装"})
	}
	return core.Check{
		Category: item.Category, Item: item.Name, Expected: "已停止、已禁用",
		Actual: actual, Conclusion: conclusion, Details: details,
	}
}
