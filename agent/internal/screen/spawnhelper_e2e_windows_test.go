//go:build windows

package screen

import (
	"context"
	"os"
	"testing"
)

// This is a real, end-to-end exercise of spawnHelperSession -- CreateProcessAsUser
// into a session, two named pipes, and a real spawned helper process actually
// doing GDI capture and SendInput -- not just a check that the code compiles.
// FLEETVIEW_REAL_AGENT_EXE must point at a real fleetview-agent.exe build (the
// go test binary itself has no --fleetview-screen-helper handling, so it can
// never behave as the helper); the test is skipped if that's unset, same
// degrade-to-skip pattern screen_windows_test.go already uses for "no active
// console session".
func TestSpawnHelperSessionEndToEnd(t *testing.T) {
	exe := os.Getenv("FLEETVIEW_REAL_AGENT_EXE")
	if exe == "" {
		t.Skip("FLEETVIEW_REAL_AGENT_EXE not set")
	}
	helperExecutablePath = func() (string, error) { return exe, nil }
	defer func() { helperExecutablePath = os.Executable }()

	own, err := currentSessionID()
	if err != nil {
		t.Fatalf("currentSessionID: %v", err)
	}
	// There's only ever one session in this (Wine) environment, so this
	// targets our own session -- it can't exercise crossing a real session
	// boundary, but it does exercise every other part of the real path:
	// SeTcbPrivilege, WTSQueryUserToken, DuplicateTokenEx,
	// CreateEnvironmentBlock, CreateProcessAsUser, the named pipes (with
	// their custom security descriptor), and the real spawned helper
	// process actually capturing and injecting input.
	session, err := spawnHelperSession(own)
	if err != nil {
		t.Fatalf("spawnHelperSession: %v", err)
	}
	defer session.Close()

	frame, width, height, err := session.Capture(context.Background())
	if err != nil {
		t.Fatalf("Capture via helper: %v", err)
	}
	if len(frame) < 100 || frame[0] != 0xFF || frame[1] != 0xD8 {
		t.Fatalf("expected a real JPEG via the helper, got %d bytes", len(frame))
	}
	t.Logf("captured %dx%d via a real spawned helper process, %d bytes", width, height, len(frame))

	if err := session.MouseMove(0.4, 0.6); err != nil {
		t.Fatalf("MouseMove via helper: %v", err)
	}
	if err := session.MouseButton(0.4, 0.6, "left", true); err != nil {
		t.Fatalf("MouseButton down via helper: %v", err)
	}
	if err := session.MouseButton(0.4, 0.6, "left", false); err != nil {
		t.Fatalf("MouseButton up via helper: %v", err)
	}
	if err := session.Key("a", true); err != nil {
		t.Fatalf("Key via helper: %v", err)
	}
	if err := session.Key("a", false); err != nil {
		t.Fatalf("Key up via helper: %v", err)
	}

	// A second real frame confirms the helper's frame loop keeps serving
	// requests rather than only ever answering the first one.
	frame2, _, _, err := session.Capture(context.Background())
	if err != nil {
		t.Fatalf("second Capture via helper: %v", err)
	}
	if len(frame2) < 100 {
		t.Fatalf("second frame too small: %d bytes", len(frame2))
	}
}
