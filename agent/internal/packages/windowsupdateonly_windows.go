package packages

import (
	"context"
	"fmt"
	"time"

	"fleetview-agent/internal/model"
)

// WindowsUpdateOnly stands in for the package Manager when winget isn't
// present (a common state on a fresh Windows install/VM, and Windows
// Server doesn't ship winget by default). Unlike NullManager, it isn't a
// complete no-op: OS-level Windows Update patch scanning uses the Windows
// Update Agent COM API, which ships with every modern Windows release
// independent of winget, so that signal -- and the ability to install
// those patches -- is still available with no third-party package manager
// installed. Only winget-specific capabilities (reporting/installing
// winget-managed applications) are unavailable.
type WindowsUpdateOnly struct {
	// Reason explains why winget specifically is unavailable, folded into
	// Install's rejection (InstallUpdates is NOT rejected -- see below).
	Reason string
}

func (WindowsUpdateOnly) Name() string { return "windows-update" }

func (WindowsUpdateOnly) Installed(context.Context) ([]model.Package, error) {
	// Winget-managed application inventory isn't available without winget;
	// Windows Update doesn't track installed applications, only pending OS
	// patches, so there is nothing to report here.
	return []model.Package{}, nil
}

func (WindowsUpdateOnly) Updates(parent context.Context) ([]model.Update, error) {
	ctx, cancel := context.WithTimeout(parent, windowsUpdateSearchTimeout)
	defer cancel()
	return windowsUpdateSearch(ctx)
}

func (WindowsUpdateOnly) InstallUpdates() (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	return installWindowsUpdates(ctx)
}

func (w WindowsUpdateOnly) Install(context.Context, string) (string, int, error) {
	return "", 0, fmt.Errorf("no application package manager available on this device: %s", w.Reason)
}
