package packages

import "context"

// installPendingWindowsUpdates lets InstallApproved (approved.go, no build
// tag) install the OS-level Windows Update patches merged into a Winget
// device's update list without needing a Winget-specific build-tagged
// file of its own: winget's own "winget upgrade --all" never touches
// these (they aren't in winget's catalog at all), so approving one on a
// device that also has winget still needs this same COM-API installer
// WindowsUpdateOnly.InstallUpdates already uses when winget is absent.
func installPendingWindowsUpdates(ctx context.Context) (string, int, error) {
	return installWindowsUpdates(ctx)
}
