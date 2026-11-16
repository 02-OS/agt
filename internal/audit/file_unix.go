//go:build !windows

package audit

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func openPrivateNoFollow(path string, flags int, perm os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(path, flags|syscall.O_NOFOLLOW, perm)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("audit log is a symlink")
		}
		return nil, err
	}
	return f, nil
}

func lockAuditFile(f *os.File) (func(), error) {
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return nil, fmt.Errorf("lock audit log: %w", err)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	}, nil
}
