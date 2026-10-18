package packages

import (
	"fmt"
	"os/exec"
)

func Detect() (Manager, error) {
	if _, err := exec.LookPath("pkg"); err != nil {
		return nil, fmt.Errorf("no supported package manager detected (supported: pkg): %w", err)
	}
	return Pkg{}, nil
}
