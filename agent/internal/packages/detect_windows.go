package packages

import (
	"fmt"
	"os/exec"
)

func Detect() (Manager, error) {
	if _, err := exec.LookPath("winget"); err != nil {
		return nil, fmt.Errorf("winget not found; install App Installer from the Microsoft Store: %w", err)
	}
	return Winget{}, nil
}
