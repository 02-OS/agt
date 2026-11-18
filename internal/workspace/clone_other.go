//go:build !linux && !darwin

package workspace

import "os"

func tryReflink(_, _ string, _ os.FileMode) bool {
	return false
}
