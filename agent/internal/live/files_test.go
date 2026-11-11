package live

import (
	"os"
	"path/filepath"
	"testing"
)

func newTestFilesHandler(t *testing.T) (*filesHandler, func() []any) {
	t.Helper()
	var sent []any
	handler := &filesHandler{send: func(payload any) { sent = append(sent, payload) }}
	return handler, func() []any { return sent }
}

func TestDeleteRemovesAFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "doomed.txt")
	if err := os.WriteFile(path, []byte("bye"), 0o644); err != nil {
		t.Fatal(err)
	}
	handler, sent := newTestFilesHandler(t)
	handler.delete("s1", path, false)

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be gone, stat error: %v", path, err)
	}
	result := sent()[0].(filesDeleteResult)
	if result.Error != "" {
		t.Fatalf("unexpected error: %s", result.Error)
	}
}

func TestDeleteRefusesANonEmptyDirectoryWithoutRecursive(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "populated")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "child.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	handler, sent := newTestFilesHandler(t)
	handler.delete("s1", sub, false)

	if _, err := os.Stat(sub); err != nil {
		t.Fatalf("expected %s to still exist, got: %v", sub, err)
	}
	result := sent()[0].(filesDeleteResult)
	if result.Error == "" {
		t.Fatal("expected an error for a non-empty directory without recursive")
	}
}

func TestDeleteRecursiveRemovesAnEntireDirectoryTree(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "populated")
	if err := os.MkdirAll(filepath.Join(sub, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "nested", "child.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	handler, sent := newTestFilesHandler(t)
	handler.delete("s1", sub, true)

	if _, err := os.Stat(sub); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be gone, stat error: %v", sub, err)
	}
	result := sent()[0].(filesDeleteResult)
	if result.Error != "" {
		t.Fatalf("unexpected error: %s", result.Error)
	}
}

func TestDeleteReportsAMissingPath(t *testing.T) {
	handler, sent := newTestFilesHandler(t)
	handler.delete("s1", filepath.Join(t.TempDir(), "never-existed"), false)

	result := sent()[0].(filesDeleteResult)
	if result.Error == "" {
		t.Fatal("expected an error for a path that was never there")
	}
}

func TestDeleteRejectsAnEmptyPath(t *testing.T) {
	handler, sent := newTestFilesHandler(t)
	handler.delete("s1", "", false)

	result := sent()[0].(filesDeleteResult)
	if result.Error == "" {
		t.Fatal("expected an error for an empty path")
	}
}
