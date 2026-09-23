package main

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

func TestRunCommandSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash-based test; Windows path uses PowerShell and isn't exercised here")
	}
	output, code, err := runCommand(context.Background(), "echo hello-fleetview")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(output, "hello-fleetview") {
		t.Fatalf("expected output to contain the echoed text, got %q", output)
	}
}

func TestRunCommandFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash-based test; Windows path uses PowerShell and isn't exercised here")
	}
	output, code, err := runCommand(context.Background(), "echo oops >&2; exit 7")
	if err == nil {
		t.Fatal("expected an error for a non-zero exit")
	}
	if code != 7 {
		t.Fatalf("expected exit code 7, got %d", code)
	}
	if !strings.Contains(output, "oops") {
		t.Fatalf("expected captured stderr in output, got %q", output)
	}
}

func TestRunCommandOutputTruncation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash-based test; Windows path uses PowerShell and isn't exercised here")
	}
	// Print well over 1 MiB so truncation to the trailing 1 MiB kicks in.
	output, _, _ := runCommand(context.Background(), "head -c 2000000 /dev/zero | tr '\\0' 'a'")
	if len(output) > 1_048_576 {
		t.Fatalf("expected output truncated to 1MiB, got %d bytes", len(output))
	}
}
