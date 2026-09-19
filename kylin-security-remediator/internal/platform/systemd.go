package platform

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/services"
)

type SystemdBackend struct {
	run func(context.Context, ...string) ([]byte, error)
}

func (b SystemdBackend) State(ctx context.Context, name string) (services.State, error) {
	loadOutput, loadErr := b.command(ctx, "show", name, "--property=LoadState", "--value")
	loadState := strings.TrimSpace(string(loadOutput))
	if loadErr != nil {
		if loadState == "not-found" {
			return services.State{}, nil
		}
		return services.State{}, fmt.Errorf("读取服务加载状态 %s: %w: %s", name, loadErr, loadState)
	}
	if loadState == "not-found" {
		return services.State{}, nil
	}
	if loadState == "" {
		return services.State{}, fmt.Errorf("读取服务加载状态 %s: systemctl 返回空结果", name)
	}
	activeOutput, activeErr := b.command(ctx, "is-active", name)
	activeState := strings.TrimSpace(string(activeOutput))
	if activeErr != nil && !knownInactiveState(activeState) {
		return services.State{}, fmt.Errorf("读取服务运行状态 %s: %w: %s", name, activeErr, activeState)
	}
	enabledOutput, enabledErr := b.command(ctx, "is-enabled", name)
	enabledState := strings.TrimSpace(string(enabledOutput))
	if enabledErr != nil && !knownDisabledState(enabledState) {
		return services.State{}, fmt.Errorf("读取服务启用状态 %s: %w: %s", name, enabledErr, enabledState)
	}
	idOutput, idErr := b.command(ctx, "show", name, "--property=Id", "--value")
	canonical := strings.TrimSpace(string(idOutput))
	if idErr != nil {
		return services.State{}, fmt.Errorf("读取服务规范名称 %s: %w: %s", name, idErr, canonical)
	}
	if canonical == "" {
		return services.State{}, fmt.Errorf("读取服务规范名称 %s: systemctl 返回空结果", name)
	}
	return services.State{
		Exists:    true,
		Active:    activeState == "active",
		Enabled:   enabledState == "enabled" || enabledState == "enabled-runtime",
		Canonical: canonical,
	}, nil
}

func knownInactiveState(state string) bool {
	switch state {
	case "inactive", "failed", "activating", "deactivating", "reloading":
		return true
	default:
		return false
	}
}

func knownDisabledState(state string) bool {
	switch state {
	case "disabled", "static", "indirect", "masked", "generated", "transient", "linked", "linked-runtime", "alias":
		return true
	default:
		return false
	}
}

func (b SystemdBackend) DisableNow(ctx context.Context, name string) error {
	output, err := b.command(ctx, "disable", "--now", name)
	if err != nil {
		return fmt.Errorf("%v: %s", err, output)
	}
	return nil
}

func (b SystemdBackend) Restore(ctx context.Context, name string, state services.State) error {
	if state.Enabled {
		output, err := b.command(ctx, "enable", name)
		if err != nil {
			return fmt.Errorf("恢复开机启用 %s: %v: %s", name, err, output)
		}
	}
	if state.Active {
		output, err := b.command(ctx, "start", name)
		if err != nil {
			return fmt.Errorf("恢复运行状态 %s: %v: %s", name, err, output)
		}
	}
	return nil
}

func (b SystemdBackend) command(ctx context.Context, args ...string) ([]byte, error) {
	if b.run != nil {
		return b.run(ctx, args...)
	}
	return exec.CommandContext(ctx, "/bin/systemctl", args...).CombinedOutput()
}
