package packages

import (
	"fmt"
	"os/exec"
)

func Detect() (Manager, error) {
	if _, err := exec.LookPath("pacman"); err == nil {
		if _, err := exec.LookPath("checkupdates"); err != nil {
			return nil, fmt.Errorf("checkupdates not found; install pacman-contrib: %w", err)
		}
		return Pacman{}, nil
	}
	if _, aptErr := exec.LookPath("apt-get"); aptErr == nil {
		if _, dpkgErr := exec.LookPath("dpkg-query"); dpkgErr != nil {
			return nil, fmt.Errorf("dpkg-query not found: %w", dpkgErr)
		}
		return APT{}, nil
	}
	return nil, fmt.Errorf("no supported package manager detected (supported: pacman, apt)")
}
