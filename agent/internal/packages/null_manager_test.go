package packages

import (
	"context"
	"strings"
	"testing"
)

// Confirms NullManager satisfies Manager at compile time -- a missing
// method here would be a compile error, not a test failure, but keeping
// the assertion explicit documents the intent.
var _ Manager = NullManager{}

func TestNullManager_ReadsReturnEmptyNotNil(t *testing.T) {
	m := NullManager{Reason: "winget not found"}
	installed, err := m.Installed(context.Background())
	if err != nil {
		t.Fatalf("Installed returned error: %v", err)
	}
	if installed == nil {
		t.Fatalf("Installed returned a nil slice; the agent JSON-encodes this as the report's installed_packages field, and the server requires a list, not null")
	}
	if len(installed) != 0 {
		t.Fatalf("Installed returned %d items, want 0", len(installed))
	}

	updates, err := m.Updates(context.Background())
	if err != nil {
		t.Fatalf("Updates returned error: %v", err)
	}
	if updates == nil {
		t.Fatalf("Updates returned a nil slice; same null-vs-[] concern as Installed")
	}
	if len(updates) != 0 {
		t.Fatalf("Updates returned %d items, want 0", len(updates))
	}
}

func TestNullManager_WriteActionsRejectedWithReason(t *testing.T) {
	m := NullManager{Reason: "winget not found; install App Installer from the Microsoft Store"}

	if _, _, err := m.InstallUpdates(); err == nil {
		t.Fatalf("InstallUpdates should fail with no package manager available")
	} else if !strings.Contains(err.Error(), "winget not found") {
		t.Fatalf("InstallUpdates error %q should include the original reason", err.Error())
	}

	if _, _, err := m.Install(context.Background(), "some-package"); err == nil {
		t.Fatalf("Install should fail with no package manager available")
	} else if !strings.Contains(err.Error(), "winget not found") {
		t.Fatalf("Install error %q should include the original reason", err.Error())
	}
}

func TestNullManager_NameIsStable(t *testing.T) {
	// Fed into vulnerability.Detect(manager.Name()), which already falls
	// through to a clear "no scanner available" error for any name it
	// doesn't recognize -- this just confirms Name() doesn't panic or
	// return something that would collide with a real manager's name
	// ("apt", "pacman", "winget").
	m := NullManager{}
	switch m.Name() {
	case "apt", "pacman", "winget":
		t.Fatalf("NullManager.Name() = %q collides with a real package manager's name", m.Name())
	}
}
