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
