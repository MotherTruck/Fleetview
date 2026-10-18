package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateServerURLReplacesExistingLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.env")
	original := "FLEETVIEW_SERVER_URL=http://old.example\nFLEETVIEW_ENROLLMENT_TOKEN=fv_abc\nFLEETVIEW_SCAN_INTERVAL_SECONDS=900\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if err := UpdateServerURL(path, "https://new.example"); err != nil {
		t.Fatalf("UpdateServerURL: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "FLEETVIEW_SERVER_URL=https://new.example\n") {
		t.Fatalf("server URL not updated, got:\n%s", text)
	}
	if !strings.Contains(text, "FLEETVIEW_ENROLLMENT_TOKEN=fv_abc") {
		t.Fatalf("other config lines were not preserved, got:\n%s", text)
	}
	if strings.Contains(text, "http://old.example") {
		t.Fatalf("old server URL still present, got:\n%s", text)
	}
	// Only one FLEETVIEW_SERVER_URL line should remain, not an appended duplicate.
	if strings.Count(text, "FLEETVIEW_SERVER_URL=") != 1 {
		t.Fatalf("expected exactly one FLEETVIEW_SERVER_URL line, got:\n%s", text)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load after update: %v", err)
	}
	if cfg.ServerURL != "https://new.example" {
		t.Fatalf("Load() returned ServerURL=%q, want https://new.example", cfg.ServerURL)
	}
}

func TestLoadRefusesPlaintextToNonLocalAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.env")
	if err := os.WriteFile(path, []byte("FLEETVIEW_SERVER_URL=http://192.168.1.50:8080\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected Load to refuse plain HTTP to a non-local address")
	}
	if !strings.Contains(err.Error(), "FLEETVIEW_ALLOW_PLAINTEXT") {
		t.Fatalf("expected the error to mention the opt-out, got: %v", err)
	}
}

func TestLoadAllowsPlaintextWithExplicitOptOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.env")
	content := "FLEETVIEW_SERVER_URL=http://192.168.1.50:8080\nFLEETVIEW_ALLOW_PLAINTEXT=true\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load with explicit opt-out: %v", err)
	}
	if cfg.ServerURL != "http://192.168.1.50:8080" {
		t.Fatalf("ServerURL = %q", cfg.ServerURL)
	}
}

func TestLoadAllowsPlaintextLoopbackByDefault(t *testing.T) {
	for _, serverURL := range []string{"http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080"} {
		path := filepath.Join(t.TempDir(), "agent.env")
		if err := os.WriteFile(path, []byte("FLEETVIEW_SERVER_URL="+serverURL+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err != nil {
			t.Errorf("Load(%q) should not require FLEETVIEW_ALLOW_PLAINTEXT for loopback, got: %v", serverURL, err)
		}
	}
}

func TestLoadAllowsHTTPSToAnyAddressWithoutOptOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.env")
	if err := os.WriteFile(path, []byte("FLEETVIEW_SERVER_URL=https://fleet.example.com:8443\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load with https:// should not require FLEETVIEW_ALLOW_PLAINTEXT, got: %v", err)
	}
}

func TestUpdateServerURLAppendsWhenMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.env")
	if err := os.WriteFile(path, []byte("FLEETVIEW_SCAN_INTERVAL_SECONDS=900\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := UpdateServerURL(path, "https://new.example"); err != nil {
		t.Fatalf("UpdateServerURL: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load after update: %v", err)
	}
	if cfg.ServerURL != "https://new.example" {
		t.Fatalf("Load() returned ServerURL=%q, want https://new.example", cfg.ServerURL)
	}
}
