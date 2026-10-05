package packages

import "testing"

func TestParseWindowsUpdateSearchEmpty(t *testing.T) {
	for _, input := range []string{"", "  \n", "null"} {
		updates, err := parseWindowsUpdateSearch([]byte(input))
		if err != nil {
			t.Fatalf("input %q: %v", input, err)
		}
		if len(updates) != 0 {
			t.Fatalf("input %q: expected no updates, got %#v", input, updates)
		}
	}
}

// PowerShell's ConvertTo-Json unwraps a single-element array into a bare
// object unless -InputObject is used to prevent it; parseWindowsUpdateSearch
// must tolerate both shapes regardless.
func TestParseWindowsUpdateSearchSingleObject(t *testing.T) {
	input := `{"Title":"2024-01 Cumulative Update","KB":"KB5034123","Severity":"Critical"}`
	updates, err := parseWindowsUpdateSearch([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) != 1 {
		t.Fatalf("expected 1 update, got %#v", updates)
	}
	u := updates[0]
	if u.Package != "Windows Update: 2024-01 Cumulative Update (KB5034123)" {
		t.Fatalf("unexpected package name: %q", u.Package)
	}
	if u.AvailableVersion != "KB5034123" {
		t.Fatalf("unexpected available version: %q", u.AvailableVersion)
	}
	if u.Identifier != "KB5034123" {
		t.Fatalf("expected Identifier to be the KB number so the server's approval view doesn't drop this entry (its free-text Package name contains spaces/parens), got %q", u.Identifier)
	}
	if u.SecurityUpdate == nil || !*u.SecurityUpdate {
		t.Fatalf("expected SecurityUpdate=true, got %#v", u.SecurityUpdate)
	}
	if u.RebootRequired == nil || !*u.RebootRequired {
		t.Fatalf("expected RebootRequired=true, got %#v", u.RebootRequired)
	}
}

func TestParseWindowsUpdateSearchArray(t *testing.T) {
	input := `[{"Title":"Feature update","KB":"","Severity":""},{"Title":"Security update","KB":"KB1111111","Severity":"Important"}]`
	updates, err := parseWindowsUpdateSearch([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) != 2 {
		t.Fatalf("expected 2 updates, got %#v", updates)
	}
	if updates[0].Package != "Windows Update: Feature update" {
		t.Fatalf("unexpected first package name: %q", updates[0].Package)
	}
	if updates[0].Identifier != "" {
		t.Fatalf("expected no Identifier for a KB-less entry, got %q", updates[0].Identifier)
	}
	if updates[1].Identifier != "KB1111111" {
		t.Fatalf("expected Identifier to be the KB number, got %q", updates[1].Identifier)
	}
	if updates[0].SecurityUpdate == nil || *updates[0].SecurityUpdate {
		t.Fatalf("expected first update to not be flagged security, got %#v", updates[0].SecurityUpdate)
	}
	if updates[1].SecurityUpdate == nil || !*updates[1].SecurityUpdate {
		t.Fatalf("expected second update to be flagged security, got %#v", updates[1].SecurityUpdate)
	}
}

func TestParseWindowsUpdateSearchEmptyArray(t *testing.T) {
	updates, err := parseWindowsUpdateSearch([]byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) != 0 {
		t.Fatalf("expected no updates, got %#v", updates)
	}
}
