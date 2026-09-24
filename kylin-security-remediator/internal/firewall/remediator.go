package firewall

import (
	"context"
	"fmt"
	"strings"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/core"
)

type Backend interface {
	Save(context.Context) (string, error)
	Run(context.Context, []string) error
}

type Remediator struct {
	backend Backend
}

func NewRemediator(backend Backend) *Remediator {
	return &Remediator{backend: backend}
}

func (r *Remediator) Evaluate(ctx context.Context, mode core.Mode) ([]core.Check, []core.Action, error) {
	before, err := r.backend.Save(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("读取 iptables: %w", err)
	}
	if covered, missing, managed := cemsCoverage(before); managed {
		legacyPlan := legacyCleanupPlan(before)
		if mode == core.ModeAudit || len(legacyPlan) == 0 {
			return []core.Check{cemsFirewallCheck(covered, missing, len(legacyPlan))}, nil, nil
		}
		actions, err := r.apply(ctx, legacyPlan)
		if err != nil {
			return nil, actions, err
		}
		after, err := r.backend.Save(ctx)
		if err != nil {
			return nil, actions, fmt.Errorf("复检 iptables: %w", err)
		}
		remainingLegacy := legacyCleanupPlan(after)
		if len(remainingLegacy) != 0 {
			for index := range actions {
				actions[index].Status = "被安全策略覆盖"
			}
		}
		covered, missing, _ = cemsCoverage(after)
		return []core.Check{cemsFirewallCheck(covered, missing, len(remainingLegacy))}, actions, nil
	}
	plan, err := BuildPlan(before)
	if err != nil {
		return nil, nil, err
	}
	if mode == core.ModeAudit {
		return []core.Check{firewallCheck(len(plan) == 0, plan)}, nil, nil
	}
	actions, err := r.apply(ctx, plan)
	if err != nil {
		return nil, actions, err
	}
	after, err := r.backend.Save(ctx)
	if err != nil {
		return nil, actions, fmt.Errorf("复检 iptables: %w", err)
	}
	remaining, err := BuildPlan(after)
	if err != nil {
		return nil, actions, err
	}
	if len(remaining) != 0 {
		for index := range actions {
			actions[index].Status = "被安全策略覆盖"
		}
		return []core.Check{firewallOverrideCheck(remaining)}, actions, nil
	}
	return []core.Check{firewallCheck(len(remaining) == 0, remaining)}, actions, nil
}

func cemsFirewallCheck(covered, missing []portRule, legacyCount int) core.Check {
	check := core.Check{
		Category:   "防火墙",
		Item:       "高危端口入站阻断规则",
		Expected:   "8项高危端口均由CEMS通用入站策略阻断，且无本程序遗留的136端口规则",
		Actual:     fmt.Sprintf("CEMS已覆盖%d项，管理端待补%d项；本程序未修改本机iptables规则", len(covered), len(missing)),
		Conclusion: core.ConclusionFail,
		Details: []core.Detail{
			{Name: "数据来源", Value: "iptables-save（filter表）"},
			{Name: "管理方式", Value: "检测到CEMS接管INPUT；仅审计，不与CEMS争抢规则顺序"},
			{Name: "审计范围", Value: "按CEMS_COMMON_INPUT通用策略判断；CEMS_SUPIN/OFFNET等来源例外仍由CEMS管理，须以外部端口探测最终验收"},
			{Name: "CEMS已覆盖", Value: formatPortRules(covered)},
		},
	}
	if legacyCount > 0 {
		check.Details = append(check.Details, core.Detail{Name: "本程序遗留规则", Value: fmt.Sprintf("检测到%d条TCP/UDP 136阻断规则，修复模式将只删除这些遗留规则", legacyCount)})
	}
	if len(missing) == 0 && legacyCount == 0 {
		check.Actual = "CEMS已覆盖8项，本程序未修改CEMS规则"
		check.Conclusion = core.ConclusionPass
		check.Details = append(check.Details, core.Detail{Name: "核验结果", Value: "无需补充"})
		return check
	}
	for index, rule := range missing {
		check.Details = append(check.Details, core.Detail{
			Name:  fmt.Sprintf("CEMS管理端待补%02d", index+1),
			Value: formatPortRule(rule) + " 入站阻断",
		})
	}
	return check
}

func formatPortRules(rules []portRule) string {
	if len(rules) == 0 {
		return "无"
	}
	values := make([]string, 0, len(rules))
	for _, rule := range rules {
		values = append(values, formatPortRule(rule))
	}
	return strings.Join(values, "、")
}

func formatPortRule(rule portRule) string {
	return strings.ToUpper(rule.Protocol) + " " + fmt.Sprint(rule.Port)
}

func firewallOverrideCheck(remaining []Command) core.Check {
	return core.Check{
		Category:   "防火墙",
		Item:       "高危端口入站阻断规则",
		Expected:   "8项规则完整且无重复，并优先于第三方规则链",
		Actual:     fmt.Sprintf("安全策略覆盖，本次阻断未保持，仍需%d项调整；程序未循环争抢规则", len(remaining)),
		Conclusion: core.ConclusionFail,
		Details:    firewallDetails(remaining),
	}
}

func (r *Remediator) rollback(ctx context.Context, applied []Command) error {
	for index := len(applied) - 1; index >= 0; index-- {
		if err := r.backend.Run(ctx, applied[index].Undo); err != nil {
			return err
		}
	}
	return nil
}

func (r *Remediator) apply(ctx context.Context, plan []Command) ([]core.Action, error) {
	var actions []core.Action
	var applied []Command
	for _, command := range plan {
		if err := r.backend.Run(ctx, command.Args); err != nil {
			rollbackErr := r.rollback(ctx, applied)
			markRolledBack(actions)
			if rollbackErr != nil {
				return actions, fmt.Errorf("执行 iptables %s: %w；回滚失败: %v", strings.Join(command.Args, " "), err, rollbackErr)
			}
			return actions, fmt.Errorf("执行 iptables %s: %w；已回滚", strings.Join(command.Args, " "), err)
		}
		applied = append(applied, command)
		actions = append(actions, core.Action{Kind: "iptables", Target: strings.Join(command.Args, " "), Status: "成功"})
	}
	return actions, nil
}

func markRolledBack(actions []core.Action) {
	for index := range actions {
		actions[index].Status = "已回滚"
	}
}

func firewallCheck(pass bool, remaining []Command) core.Check {
	check := core.Check{
		Category:   "防火墙",
		Item:       "高危端口入站阻断规则",
		Expected:   "8项规则完整且无重复，并优先于第三方规则链",
		Actual:     fmt.Sprintf("仍需执行%d项调整", len(remaining)),
		Conclusion: core.ConclusionFail,
		Details:    firewallDetails(remaining),
	}
	if pass {
		check.Actual = "8项规则完整、无重复且位于INPUT首位"
		check.Conclusion = core.ConclusionPass
	}
	return check
}

func firewallDetails(plan []Command) []core.Detail {
	details := []core.Detail{
		{Name: "数据来源", Value: "iptables-save（filter表）"},
		{Name: "受控规则链", Value: Chain},
		{Name: "目标阻断规则", Value: "TCP 22、135、139、445、3389；UDP 137、138、3389"},
	}
	if len(plan) == 0 {
		return append(details, core.Detail{Name: "核验结果", Value: "8项规则均存在且无重复，INPUT首条跳转到受控规则链"})
	}
	for index, command := range plan {
		details = append(details, core.Detail{Name: fmt.Sprintf("待调整%02d", index+1), Value: strings.Join(command.Args, " ")})
	}
	return details
}
