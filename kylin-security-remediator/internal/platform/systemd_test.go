package platform

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSystemdStateDoesNotReportMissingServiceWhenSystemctlReadFails(t *testing.T) {
	backend := SystemdBackend{run: func(context.Context, ...string) ([]byte, error) {
		return []byte("Failed to connect to bus: Permission denied"), errors.New("exit status 1")
	}}

	state, err := backend.State(context.Background(), "sshd.service")
	if err == nil || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("State() = %#v, %v; want explicit data-source failure", state, err)
	}
}

func TestSystemdStateDoesNotReportStoppedWhenActiveStateReadFails(t *testing.T) {
	backend := SystemdBackend{run: func(_ context.Context, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "is-active" {
			return []byte("Failed to connect to bus: Permission denied"), errors.New("exit status 1")
		}
		if len(args) > 0 && args[0] == "is-enabled" {
			return []byte("disabled"), errors.New("exit status 1")
		}
		if len(args) > 2 && args[2] == "--property=Id" {
			return []byte("sshd.service"), nil
		}
		return []byte("loaded"), nil
	}}

	state, err := backend.State(context.Background(), "sshd.service")
	if err == nil || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("State() = %#v, %v; want active-state failure", state, err)
	}
}

func TestSystemdStateDoesNotReportDisabledWhenEnablementReadFails(t *testing.T) {
	backend := SystemdBackend{run: func(_ context.Context, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "is-active" {
			return []byte("inactive"), errors.New("exit status 3")
		}
		if len(args) > 0 && args[0] == "is-enabled" {
			return []byte("Failed to connect to bus: Permission denied"), errors.New("exit status 1")
		}
		if len(args) > 2 && args[2] == "--property=Id" {
			return []byte("sshd.service"), nil
		}
		return []byte("loaded"), nil
	}}

	state, err := backend.State(context.Background(), "sshd.service")
	if err == nil || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("State() = %#v, %v; want enablement-state failure", state, err)
	}
}

func TestSystemdStateDoesNotLoseCanonicalUnitWhenIdentityReadFails(t *testing.T) {
	backend := SystemdBackend{run: func(_ context.Context, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "is-active" {
			return []byte("inactive"), errors.New("exit status 3")
		}
		if len(args) > 0 && args[0] == "is-enabled" {
			return []byte("disabled"), errors.New("exit status 1")
		}
		if len(args) > 2 && args[2] == "--property=Id" {
			return []byte("Failed to connect to bus"), errors.New("exit status 1")
		}
		return []byte("loaded"), nil
	}}

	state, err := backend.State(context.Background(), "sshd.service")
	if err == nil || !strings.Contains(err.Error(), "connect to bus") {
		t.Fatalf("State() = %#v, %v; want canonical-unit failure", state, err)
	}
}
