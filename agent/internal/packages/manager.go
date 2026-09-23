package packages

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"time"

	"fleetview-agent/internal/model"
)

type Manager interface {
	Name() string
	Installed(context.Context) ([]model.Package, error)
	Updates(context.Context) ([]model.Update, error)
	InstallUpdates() (string, int, error)
	// Install deploys a single named package that is not necessarily already
	// installed (unlike InstallUpdates, which only upgrades what's already
	// present). packageName is platform-specific: a pacman/apt package name,
	// or a winget package ID on Windows.
	Install(ctx context.Context, packageName string) (output string, exitCode int, err error)
}

var literalPackage = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+:-]{0,254}$`)

// Uninstall intentionally avoids purge, autoremove, recursive removal, and
// dependency overrides. Package-manager dependency safety checks stay enabled.
func Uninstall(parent context.Context, manager string, name string) (string, int, error) {
	if !literalPackage.MatchString(name) {
		return "", -1, fmt.Errorf("a single literal package name or ID is required")
	}
	var args []string
	var executable string
	switch manager {
	case "apt":
		executable, args = "apt-get", []string{"-y", "remove", "--", name}
	case "pacman":
		executable, args = "pacman", []string{"-R", "--noconfirm", "--", name}
	case "winget":
		executable, args = "winget", []string{"uninstall", "--id", name, "--exact", "--silent", "--disable-interactivity", "--accept-source-agreements"}
	default:
		return "", -1, fmt.Errorf("uninstall unsupported for %q", manager)
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Minute)
	defer cancel()
	output, err := exec.CommandContext(ctx, executable, args...).CombinedOutput()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return truncate(string(output), 1_048_576), exitCode(err), err
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[len(value)-max:]
}
