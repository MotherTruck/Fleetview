package config

import (
	"os"
	"path/filepath"
)

func defaultStatePath() string {
	return filepath.Join(programDataDir(), "state.json")
}

func programDataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "fleetview-agent")
}
