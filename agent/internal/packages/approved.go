package packages

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"fleetview-agent/internal/model"
)

var aptPlannedInstall = regexp.MustCompile(`(?m)^Inst ([^ ]+) (?:\[[^\]]+\] )?\(([^ ]+) `)

// kernelFamilyPackage matches a kernel meta-package (e.g. linux-image-amd64)
// as well as the concrete versioned package it depends on (e.g.
// linux-image-6.12.113+deb13-amd64). Approving the meta-package's upgrade
// is how a kernel update is actually offered for approval -- `apt list
// --upgradable` reports only the meta-package name, since the concrete
// kernel/headers/modules package it pulls in is a brand new install, not an
// in-place upgrade of anything already present. Requiring that concrete
// package to also appear in the approved set verbatim would make approving
// any kernel update impossible, so it's allowed as an implied consequence
// of approving a kernel-family package.
var kernelFamilyPackage = regexp.MustCompile(`^linux-(image|headers|modules|modules-extra)-`)

// InstallApproved rejects stale approvals before changing packages. Apt's
// simulated transaction must contain exactly the approved packages/versions;
// dependency changes outside that set need their own approval.
func InstallApproved(parent context.Context, manager Manager, approved []model.ApprovedUpdate) (string, int, error) {
	if len(approved) == 0 || len(approved) > 2000 {
		return "", -1, fmt.Errorf("one to 2000 approved updates are required")
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Hour)
	defer cancel()
	live, err := manager.Updates(ctx)
	if err != nil {
		return "", -1, fmt.Errorf("refresh patches: %w", err)
	}
	available := make(map[string]string, len(live))
	for _, patch := range live {
		// Mirrors the server's own patch_key precedence (deployment.rs):
		// identifier first, falling back to the free-text package name.
		// Needed for any entry with a real Identifier, not just winget's
		// own packages -- the OS Windows Update entries both Winget and
		// WindowsUpdateOnly report carry a KB-number Identifier too (see
		// entriesToUpdates, windowsupdatetable.go), and the approved list
		// the server sends back is keyed the same way.
		key := patch.Package
		if patch.Identifier != "" {
			key = patch.Identifier
		}
		if key != "" {
			available[key] = patch.AvailableVersion
		}
	}
	wanted := make(map[string]string, len(approved))
	for _, patch := range approved {
		if !literalPackage.MatchString(patch.Package) || patch.Version == "" || len(patch.Version) > 255 || strings.ContainsAny(patch.Version, "\r\n\x00") {
			return "", -1, fmt.Errorf("invalid approved package or version")
		}
		if _, exists := wanted[patch.Package]; exists {
			return "", -1, fmt.Errorf("duplicate approved package")
		}
		if available[patch.Package] != patch.Version {
			return "", -1, fmt.Errorf("approved version for %s is no longer pending; scan and approve again", patch.Package)
		}
		wanted[patch.Package] = patch.Version
	}
	switch manager.Name() {
	case "pacman":
		if len(available) != len(wanted) {
			return "", -1, fmt.Errorf("Arch requires approval of every pending update")
		}
		return manager.InstallUpdates()
	case "apt":
		args := []string{"--no-install-recommends", "--no-remove", "install", "--only-upgrade"}
		for _, patch := range approved {
			args = append(args, patch.Package+"="+patch.Version)
		}
		plan := exec.CommandContext(ctx, "apt-get", append(append([]string{"-s"}, args...), aptSandboxArgs...)...)
		plan.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		preview, planErr := plan.CombinedOutput()
		if planErr != nil {
			return truncate(string(preview), 1_048_576), exitCode(planErr), planErr
		}
		if err := verifyAPTPlan(string(preview), wanted); err != nil {
			return truncate(string(preview), 1_048_576), -1, err
		}
		command := exec.CommandContext(ctx, "apt-get", append(append([]string{"-y"}, args...), aptSandboxArgs...)...)
		command.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		output, runErr := command.CombinedOutput()
		return truncate(string(output), 1_048_576), exitCode(runErr), runErr
	case "winget":
		// Entries merged in from Windows Update (see entriesToUpdates,
		// windowsupdatetable.go) are identified by a KB number, not a real
		// winget package ID -- "winget upgrade --id KB5034123" would just
		// fail, since they aren't in winget's catalog at all. Those go
		// through the same COM-API installer WindowsUpdateOnly uses when
		// winget is absent; everything else is a real winget package,
		// installed by ID as before.
		var kbApproved, appApproved []model.ApprovedUpdate
		for _, patch := range approved {
			if strings.HasPrefix(patch.Package, "KB") {
				kbApproved = append(kbApproved, patch)
			} else {
				appApproved = append(appApproved, patch)
			}
		}
		var output strings.Builder
		if len(kbApproved) > 0 {
			kbAvailable := 0
			for key := range available {
				if strings.HasPrefix(key, "KB") {
					kbAvailable++
				}
			}
			if kbAvailable != len(kbApproved) {
				return "", -1, fmt.Errorf("every pending Windows Update patch must be approved together")
			}
			kbOutput, _, kbErr := installPendingWindowsUpdates(ctx)
			output.WriteString("Windows Update:\n" + kbOutput + "\n")
			if kbErr != nil {
				return truncate(output.String(), 1_048_576), exitCode(kbErr), kbErr
			}
		}
		for _, patch := range appApproved {
			command := exec.CommandContext(ctx, "winget", "upgrade", "--id", patch.Package,
				"--exact", "--version", patch.Version, "--accept-source-agreements",
				"--accept-package-agreements", "--silent", "--disable-interactivity")
			data, runErr := command.CombinedOutput()
			output.WriteString(patch.Package + ":\n" + string(data) + "\n")
			if runErr != nil {
				return truncate(output.String(), 1_048_576), exitCode(runErr), runErr
			}
		}
		return truncate(output.String(), 1_048_576), 0, nil
	case "windows-update":
		// No app-package granularity at all here (no winget), just the OS
		// patch list -- same all-or-nothing shape as pacman, since
		// InstallUpdates() installs everything pending in one COM-API call.
		if len(available) != len(wanted) {
			return "", -1, fmt.Errorf("every pending Windows Update patch must be approved together")
		}
		return manager.InstallUpdates()
	default:
		return "", -1, fmt.Errorf("approved patch deployment unsupported for %q", manager.Name())
	}
}

func verifyAPTPlan(output string, wanted map[string]string) error {
	kernelFamilyApproved := false
	for pkg := range wanted {
		if kernelFamilyPackage.MatchString(pkg) {
			kernelFamilyApproved = true
			break
		}
	}
	changed := make(map[string]bool)
	for _, line := range strings.Split(output, "\n") {
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		matches := aptPlannedInstall.FindStringSubmatch(line)
		if matches == nil {
			return fmt.Errorf("cannot verify apt transaction")
		}
		name, version := matches[1], matches[2]
		if wanted[name] == version {
			changed[name] = true
			continue
		}
		if kernelFamilyApproved && kernelFamilyPackage.MatchString(name) {
			continue
		}
		return fmt.Errorf("apt would change unapproved package or version %s", name)
	}
	for pkg := range wanted {
		if !changed[pkg] {
			return fmt.Errorf("apt plan does not match the approved set")
		}
	}
	return nil
}
