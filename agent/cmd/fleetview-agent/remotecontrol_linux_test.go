//go:build linux

package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackageInstallCommandsPrefersAptGet(t *testing.T) {
	dir := t.TempDir()
	writeStub(t, dir, "apt-get")
	restorePath := setPathOnly(t, dir)
	defer restorePath()

	installer, argSets := packageInstallCommands([]string{"imagemagick", "xdotool"})
	if installer != "apt-get" {
		t.Fatalf("installer = %q, want apt-get", installer)
	}
	if len(argSets) != 2 || argSets[0][0] != "update" || argSets[1][0] != "install" {
		t.Fatalf("unexpected arg sets: %v", argSets)
	}
}

func TestPackageInstallCommandsFallsBackToPacman(t *testing.T) {
	dir := t.TempDir()
	writeStub(t, dir, "pacman")
	restorePath := setPathOnly(t, dir)
	defer restorePath()

	installer, argSets := packageInstallCommands([]string{"grim"})
	if installer != "pacman" {
		t.Fatalf("installer = %q, want pacman", installer)
	}
	if len(argSets) != 1 || argSets[0][0] != "-Sy" {
		t.Fatalf("unexpected arg sets: %v", argSets)
	}
}

func TestPackageInstallCommandsNoInstallerFound(t *testing.T) {
	dir := t.TempDir()
	restorePath := setPathOnly(t, dir)
	defer restorePath()

	installer, argSets := packageInstallCommands([]string{"imagemagick"})
	if installer != "" || argSets != nil {
		t.Fatalf("expected no installer, got %q %v", installer, argSets)
	}
}

// TestInstallMissingActuallyInvokesTheInstaller drives installMissing (the
// real function main.go calls at every agent startup) end-to-end against a
// fake apt-get that records its own invocations, with PATH restricted so
// neither the real "import"/"xdotool" tools nor a real package manager can
// be found -- proving the missing-tool detection, the two-step apt-get
// update+install sequence, and the actual exec.CommandContext call all work
// together, without touching this machine's real packages.
func TestInstallMissingActuallyInvokesTheInstaller(t *testing.T) {
	dir := t.TempDir()
	invocationLog := filepath.Join(dir, "invocations.log")
	writeRecordingStub(t, dir, "apt-get", invocationLog)
	restorePath := setPathOnly(t, dir)
	defer restorePath()

	installMissing(newTestLogger(), map[string]string{"import": "imagemagick", "xdotool": "xdotool"})

	data, err := os.ReadFile(invocationLog)
	if err != nil {
		t.Fatalf("apt-get was never invoked: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, "update\n") {
		t.Fatalf("expected an 'apt-get update' invocation, got: %s", got)
	}
	if !strings.Contains(got, "install -y") {
		t.Fatalf("expected an 'apt-get install -y ...' invocation, got: %s", got)
	}
	if !strings.Contains(got, "imagemagick") || !strings.Contains(got, "xdotool") {
		t.Fatalf("expected both missing packages named, got: %s", got)
	}
}

func TestInstallMissingSkipsWhenAlreadyPresent(t *testing.T) {
	dir := t.TempDir()
	writeStub(t, dir, "xdotool") // the "already installed" tool itself
	invocationLog := filepath.Join(dir, "invocations.log")
	writeRecordingStub(t, dir, "apt-get", invocationLog)
	restorePath := setPathOnly(t, dir)
	defer restorePath()

	installMissing(newTestLogger(), map[string]string{"xdotool": "xdotool"})

	if _, err := os.Stat(invocationLog); err == nil {
		t.Fatal("apt-get was invoked even though the tool was already present")
	}
}

func newTestLogger() *log.Logger {
	return log.New(os.Stderr, "test: ", 0)
}

func writeStub(t *testing.T, dir, name string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write stub %s: %v", name, err)
	}
}

// writeRecordingStub writes a fake installer that appends its own argv,
// space-joined on one line, to logPath and exits 0, so a test can assert on
// exactly what installMissing ran.
func writeRecordingStub(t *testing.T, dir, name, logPath string) {
	t.Helper()
	path := filepath.Join(dir, name)
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + logPath + "\nexit 0\n"
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatalf("write recording stub %s: %v", name, err)
	}
}

func setPathOnly(t *testing.T, dir string) (restore func()) {
	t.Helper()
	original := os.Getenv("PATH")
	if err := os.Setenv("PATH", dir); err != nil {
		t.Fatalf("set PATH: %v", err)
	}
	return func() { _ = os.Setenv("PATH", original) }
}
