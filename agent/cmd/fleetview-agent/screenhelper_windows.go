//go:build windows

package main

import (
	"fmt"
	"os"

	"fleetview-agent/internal/screen"
)

// runScreenHelperIfRequested checks for the hidden flag spawnHelperSession
// (internal/screen/remotesession_windows.go) launches this same binary
// with when it needs real GDI/SendInput access to a user's session from a
// LocalSystem service running in session 0 -- see screen.RunHelper for
// why that's a separate process at all. Checked first in main(), the same
// way runSelfInstallIfPersonalized is, since this invocation is never the
// normal agent and must never fall through to normal startup.
func runScreenHelperIfRequested() bool {
	if len(os.Args) != 4 || os.Args[1] != screen.HelperFlag {
		return false
	}
	if err := screen.RunHelper(os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, "screen helper:", err)
		os.Exit(1)
	}
	return true
}
