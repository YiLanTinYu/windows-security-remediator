package core

import "context"

type Mode string

const (
	ModeAudit  Mode = "audit"
	ModeRepair Mode = "repair"
	ModeClean  Mode = "clean"
)

const RuntimeScope = "本报告仅反映本次运行及即时复检状态；程序不安装开机服务，系统重启或安全策略刷新后应再次检查。"

type Identity struct {
	Hostname      string             `json:"hostname"`
	OS            string             `json:"os"`
	Kernel        string             `json:"kernel"`
	Arch          string             `json:"arch"`
	DesktopUser   string             `json:"desktop_user"`
	EffectiveUser string             `json:"effective_user"`
	IP            string             `json:"ip"`
	MAC           string             `json:"mac"`
	NetworkStatus string             `json:"network_status,omitempty"`
	Interfaces    []NetworkInterface `json:"interfaces"`
}

type NetworkInterface struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Up   bool   `json:"up"`
	IP   string `json:"ip"`
	MAC  string `json:"mac"`
}

type Request struct {
	Mode Mode
}

type Action struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Status string `json:"status"`
}

type Conclusion string

const (
	ConclusionPass   Conclusion = "通过"
	ConclusionFail   Conclusion = "异常"
	ConclusionReview Conclusion = "需复核"
	ConclusionNA     Conclusion = "不适用"
)

type Detail struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Check struct {
	Category   string     `json:"category"`
	Item       string     `json:"item"`
	Expected   string     `json:"expected"`
	Actual     string     `json:"actual"`
	Conclusion Conclusion `json:"conclusion"`
	Details    []Detail   `json:"details"`
}

type Result struct {
	Identity       Identity `json:"identity"`
	GeneratedAt    string   `json:"generated_at,omitempty"`
	Scope          string   `json:"scope"`
	Checks         []Check  `json:"checks"`
	BeforeChecks   []Check  `json:"before_checks,omitempty"`
	AfterChecks    []Check  `json:"after_checks,omitempty"`
	Actions        []Action `json:"actions"`
	ExecutionError string   `json:"execution_error,omitempty"`
}

type IdentityProbe interface {
	Identity(context.Context) (Identity, error)
}

type Component interface {
	Evaluate(context.Context, Mode) ([]Check, []Action, error)
}

type Engine struct {
	identity   IdentityProbe
	components []Component
}

func NewEngine(identity IdentityProbe, components ...Component) *Engine {
	return &Engine{identity: identity, components: components}
}

func (e *Engine) Run(ctx context.Context, request Request) (Result, error) {
	identity, err := e.identity.Identity(ctx)
	if err != nil {
		return Result{}, err
	}
	result := Result{Identity: identity, Scope: RuntimeScope}
	if request.Mode != ModeAudit {
		before, _, beforeErr := e.evaluate(ctx, ModeAudit)
		result.BeforeChecks = before
		result.Checks = before
		if beforeErr != nil {
			return result, beforeErr
		}
		after, actions, afterErr := e.evaluate(ctx, request.Mode)
		result.AfterChecks = after
		result.Checks = after
		result.Actions = actions
		return result, afterErr
	}
	checks, actions, componentErr := e.evaluate(ctx, request.Mode)
	result.Checks = checks
	result.Actions = actions
	return result, componentErr
}

func (e *Engine) evaluate(ctx context.Context, mode Mode) ([]Check, []Action, error) {
	var checks []Check
	var actions []Action
	for _, component := range e.components {
		componentChecks, componentActions, componentErr := component.Evaluate(ctx, mode)
		checks = append(checks, componentChecks...)
		actions = append(actions, componentActions...)
		if componentErr != nil {
			return checks, actions, componentErr
		}
	}
	return checks, actions, nil
}
