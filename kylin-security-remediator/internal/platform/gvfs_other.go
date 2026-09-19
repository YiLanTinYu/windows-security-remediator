//go:build !linux

package platform

import (
	"context"
	"io/fs"
)

func systemGVFSEntries(context.Context, string, string) ([]string, error) {
	return nil, fs.ErrNotExist
}
