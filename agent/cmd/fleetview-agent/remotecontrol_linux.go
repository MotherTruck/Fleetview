//go:build linux

package main

import (
	"context"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ensureRemoteControlDependencies best-effort installs the external tools
// agent/internal/screen's Detect() looks for: ImageMagick's `import` (X11
// screen capture) and xdotool (X11 keyboard input -- mouse motion/clicks go
// over a direct XTEST connection and need no external tool), plus grim
// (Wayland capture, view-only). Called once at every agent startup --
// including the moment a self-upgrade (UPGRADE_AGENT job) restarts the
// process, since that's how most fleets actually update -- so remote
// control needs no separate manual package install on any Linux box: the
// agent upgrade is the only step required.
//
// Best-effort and non-fatal by design: a device with no apt-get/pacman, no
// network access, or a package genuinely unavailable for its distro (grim
// is fairly recent; imagemagick/xdotool are not) simply falls back to
// whatever screen.Detect() already reports -- its Reason field explains
// exactly what's still missing, and that surfaces in the dashboard rather
// than agent startup being blocked or failing on it.
func ensureRemoteControlDependencies(logger *log.Logger) {
	installMissing(logger, map[string]string{"import": "imagemagick", "xdotool": "xdotool"})
	installMissing(logger, map[string]string{"grim": "grim"})
}

func installMissing(logger *log.Logger, toolToPackage map[string]string) {
	var packageNames []string
	for tool, pkg := range toolToPackage {
		if _, err := exec.LookPath(tool); err != nil {
			packageNames = append(packageNames, pkg)
		}
	}
	if len(packageNames) == 0 {
		return
	}
	installer, argSets := packageInstallCommands(packageNames)
	if installer == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, args := range argSets {
		cmd := exec.CommandContext(ctx, installer, args...) // #nosec G204 -- fixed installer path + known package names, no user input
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		if output, err := cmd.CombinedOutput(); err != nil {
			logger.Printf("remote control: %s %s failed: %v: %s", installer, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
			return
		}
	}
	logger.Printf("remote control: installed %s for screen capture/input support", strings.Join(packageNames, ", "))
}

// packageInstallCommands returns the installer binary and the sequence of
// argument lists to run with it (apt-get needs a separate `update` before
// `install` when packages might be missing from a stale index; pacman's
// sync database is refreshed by -Sy in the same invocation as the install).
func packageInstallCommands(packageNames []string) (string, [][]string) {
	if _, err := exec.LookPath("apt-get"); err == nil {
		return "apt-get", [][]string{{"update"}, append([]string{"install", "-y"}, packageNames...)}
	}
	if _, err := exec.LookPath("pacman"); err == nil {
		return "pacman", [][]string{append([]string{"-Sy", "--needed", "--noconfirm"}, packageNames...)}
	}
	return "", nil
}
