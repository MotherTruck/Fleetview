package packages

import (
	"fmt"
	"os/exec"
)

// Detect never fails on Windows: when winget is missing (common on a
// fresh Windows install/VM, and Windows Server doesn't ship it at all),
// WindowsUpdateOnly still covers OS-level Windows Update patch data
// independent of any third-party package manager. Returning an error here
// would make main.go fall back to the fully-inert NullManager instead,
// silently losing that patch data even though nothing about it actually
// depends on winget.
func Detect() (Manager, error) {
	if _, err := exec.LookPath("winget"); err != nil {
		return WindowsUpdateOnly{
			Reason: fmt.Sprintf("winget not found; install App Installer from the Microsoft Store: %v", err),
		}, nil
	}
	return Winget{}, nil
}
