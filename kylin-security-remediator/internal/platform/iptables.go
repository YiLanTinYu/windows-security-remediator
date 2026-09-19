package platform

import (
	"context"
	"fmt"
	"os/exec"
)

type IPTablesBackend struct {
	iptables     string
	iptablesSave string
}

func NewIPTablesBackend() IPTablesBackend {
	return IPTablesBackend{iptables: "/usr/sbin/iptables", iptablesSave: "/usr/sbin/iptables-save"}
}

func (b IPTablesBackend) Save(ctx context.Context) (string, error) {
	output, err := exec.CommandContext(ctx, b.iptablesSave).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, output)
	}
	return string(output), nil
}

func (b IPTablesBackend) Run(ctx context.Context, args []string) error {
	output, err := exec.CommandContext(ctx, b.iptables, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, output)
	}
	return nil
}
