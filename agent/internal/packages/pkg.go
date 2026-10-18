package packages

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"fleetview-agent/internal/model"
)

// Pkg wraps FreeBSD's `pkg(8)`, the package manager OPNsense itself is
// built on (OPNsense packages are an ordinary pkg repository layered on
// top of a locked-down FreeBSD base).
type Pkg struct{}

func (Pkg) Name() string { return "pkg" }

func (Pkg) Installed(ctx context.Context) ([]model.Package, error) {
	output, err := exec.CommandContext(ctx, "pkg", "query", "%n\t%v\t%q").Output()
	if err != nil {
		return nil, fmt.Errorf("pkg query: %w", err)
	}
	result := []model.Package{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) >= 2 {
			pkg := model.Package{Name: fields[0], Version: fields[1], Source: "pkg"}
			if len(fields) >= 3 {
				pkg.Architecture = fields[2]
			}
			result = append(result, pkg)
		}
	}
	return result, nil
}

// pkgUpgradeLine matches one "name: old -> new" row from `pkg upgrade -n`'s
// dry-run "Installed packages to be UPGRADED:" section.
var pkgUpgradeLine = regexp.MustCompile(`^\s*(\S+):\s+(\S+)\s+->\s+(\S+)`)

func (Pkg) Updates(ctx context.Context) ([]model.Update, error) {
	updateCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if output, err := exec.CommandContext(updateCtx, "pkg", "update", "-q").CombinedOutput(); err != nil {
		if updateCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("pkg update timed out after 5 minutes")
		}
		return nil, fmt.Errorf("pkg update: %w: %s", err, strings.TrimSpace(string(output)))
	}
	// `pkg upgrade -n` dry-runs the upgrade and exits non-zero (1) when
	// there's nothing to do (just like checkupdates on Arch) -- that's
	// the normal "up to date" case, not an error.
	output, err := exec.CommandContext(ctx, "pkg", "upgrade", "-n").CombinedOutput()
	text := string(output)
	if err != nil && !strings.Contains(text, "Installed packages to be UPGRADED") && !strings.Contains(text, "up to date") {
		return nil, fmt.Errorf("pkg upgrade -n: %w: %s", err, strings.TrimSpace(text))
	}
	result := []model.Update{}
	for _, line := range strings.Split(text, "\n") {
		match := pkgUpgradeLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		result = append(result, model.Update{Package: match[1], InstalledVersion: match[2], AvailableVersion: match[3]})
	}
	return result, nil
}

func (Pkg) InstallUpdates() (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	output, err := exec.CommandContext(ctx, "pkg", "upgrade", "-y").CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("update timed out after two hours")
	}
	return truncate(string(output), 1_048_576), exitCode(err), err
}

func (Pkg) Install(parent context.Context, packageName string) (string, int, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Minute)
	defer cancel()
	output, err := exec.CommandContext(ctx, "pkg", "install", "-y", "--", packageName).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("install timed out after 30 minutes")
	}
	return truncate(string(output), 1_048_576), exitCode(err), err
}
