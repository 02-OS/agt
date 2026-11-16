//go:build darwin

package workspace

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func tryReflink(src, dst string, mode os.FileMode) bool {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return false
	}
	_ = os.Remove(dst)
	if err := unix.Clonefile(src, dst, 0); err != nil {
		return false
	}
	perm := mode.Perm()
	if perm == 0 {
		perm = 0o644
	}
	if err := os.Chmod(dst, perm); err != nil {
		_ = os.Remove(dst)
		return false
	}
	return true
}
