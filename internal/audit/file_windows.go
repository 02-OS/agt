//go:build windows

package audit

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func openPrivateNoFollow(path string, flags int, perm os.FileMode) (*os.File, error) {
	info, err := os.Lstat(path)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("audit log is a symlink")
	}
	return os.OpenFile(path, flags, perm)
}

func lockAuditFile(f *os.File) (func(), error) {
	ol := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, ol); err != nil {
		return nil, fmt.Errorf("lock audit log: %w", err)
	}
	return func() {
		_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
	}, nil
}
