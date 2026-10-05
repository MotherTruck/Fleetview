//go:build !windows

package packages

import (
	"context"
	"fmt"
)

func installPendingWindowsUpdates(context.Context) (string, int, error) {
	return "", -1, fmt.Errorf("Windows Update installation is not available on this platform")
}
