//go:build linux

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
	in, err := os.Open(src)
	if err != nil {
		return false
	}
	defer in.Close()
	perm := mode.Perm()
	if perm == 0 {
		perm = 0o644
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return false
	}
	if err := unix.IoctlFileClone(int(out.Fd()), int(in.Fd())); err != nil {
		out.Close()
		_ = os.Remove(dst)
		return false
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(dst)
		return false
	}
	return os.Chmod(dst, perm) == nil
}
