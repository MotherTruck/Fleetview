package packages

import (
	"context"
	"strings"
	"testing"

	"fleetview-agent/internal/model"
)

// windowsApprovalManager is a configurable-name stand-in for the real
// Winget/WindowsUpdateOnly managers, used to exercise InstallApproved's
// "winget" and "windows-update" cases without a real winget or Windows
// Update install.
type windowsApprovalManager struct {
	name          string
	updates       []model.Update
	installResult string
	installCalled bool
}

func (m *windowsApprovalManager) Name() string                                       { return m.name }
func (m *windowsApprovalManager) Installed(context.Context) ([]model.Package, error) { return nil, nil }
func (m *windowsApprovalManager) Updates(context.Context) ([]model.Update, error) {
	return m.updates, nil
}
func (m *windowsApprovalManager) InstallUpdates() (string, int, error) {
	m.installCalled = true
	return m.installResult, 0, nil
}
func (m *windowsApprovalManager) Install(context.Context, string) (string, int, error) {
	panic("unexpected install")
}

func TestWindowsUpdateManagerRequiresFullApprovalBeforeInstalling(t *testing.T) {
	manager := &windowsApprovalManager{
		name: "windows-update",
		updates: []model.Update{
			{Package: "Windows Update: A (KB1)", Identifier: "KB1", AvailableVersion: "KB1"},
			{Package: "Windows Update: B (KB2)", Identifier: "KB2", AvailableVersion: "KB2"},
		},
	}
	_, _, err := InstallApproved(context.Background(), manager, []model.ApprovedUpdate{{Package: "KB1", Version: "KB1"}})
	if err == nil || !strings.Contains(err.Error(), "every pending") {
		t.Fatalf("expected a partial-approval rejection, got %v", err)
	}
	if manager.installCalled {
		t.Fatalf("InstallUpdates must not run until every pending patch is approved")
	}
}

func TestWindowsUpdateManagerInstallsOnceFullyApproved(t *testing.T) {
	manager := &windowsApprovalManager{
		name:          "windows-update",
		installResult: "installed both",
		updates: []model.Update{
			{Package: "Windows Update: A (KB1)", Identifier: "KB1", AvailableVersion: "KB1"},
			{Package: "Windows Update: B (KB2)", Identifier: "KB2", AvailableVersion: "KB2"},
		},
	}
	approved := []model.ApprovedUpdate{{Package: "KB1", Version: "KB1"}, {Package: "KB2", Version: "KB2"}}
	output, _, err := InstallApproved(context.Background(), manager, approved)
	if err != nil {
		t.Fatalf("InstallApproved: %v", err)
	}
	if !manager.installCalled {
		t.Fatalf("expected InstallUpdates to run once every pending patch was approved")
	}
	if output != "installed both" {
		t.Fatalf("expected InstallUpdates's own output to be returned, got %q", output)
	}
}

func TestWingetKBEntriesRequireFullApprovalOfTheKBSubsetOnly(t *testing.T) {
	// A real winget app update coexists with two Windows Update (KB)
	// entries; approving only one of the two KBs must be rejected without
	// touching the unrelated app update at all.
	manager := &windowsApprovalManager{
		name: "winget",
		updates: []model.Update{
			{Package: "Some App", Identifier: "Vendor.App", AvailableVersion: "2.0"},
			{Package: "Windows Update: A (KB1)", Identifier: "KB1", AvailableVersion: "KB1"},
			{Package: "Windows Update: B (KB2)", Identifier: "KB2", AvailableVersion: "KB2"},
		},
	}
	_, _, err := InstallApproved(context.Background(), manager, []model.ApprovedUpdate{{Package: "KB1", Version: "KB1"}})
	if err == nil || !strings.Contains(err.Error(), "every pending Windows Update patch") {
		t.Fatalf("expected a partial-KB-approval rejection, got %v", err)
	}
}

// On this (non-Windows) test platform, installPendingWindowsUpdates
// resolves to its _other.go stub, which always errors -- a deterministic
// way to confirm a fully-approved all-KB set is actually routed to it
// (not silently skipped, and not sent to "winget upgrade --id KB...",
// which would just fail against winget's real catalog).
func TestWingetAllKBApprovedRoutesToTheWindowsUpdateInstaller(t *testing.T) {
	manager := &windowsApprovalManager{
		name: "winget",
		updates: []model.Update{
			{Package: "Windows Update: A (KB1)", Identifier: "KB1", AvailableVersion: "KB1"},
		},
	}
	_, _, err := InstallApproved(context.Background(), manager, []model.ApprovedUpdate{{Package: "KB1", Version: "KB1"}})
	if err == nil || !strings.Contains(err.Error(), "not available on this platform") {
		t.Fatalf("expected the fully-approved KB set to reach installPendingWindowsUpdates, got %v", err)
	}
}
