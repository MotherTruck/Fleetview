//go:build linux

package main

import (
	"os"

	"fleetview-agent/internal/screen"
)

// runScreenHelperIfRequested checks for the hidden flag screen.PortalHelperFlag
// (internal/screen/portal_linux.go) launches this same binary with, dropped
// to the logged-in user's real uid/gid, to negotiate a GNOME/KDE screen-
// capture + input portal session -- see that file for why a second process
// is needed at all. Checked first in main(), the same way
// runSelfInstallIfPersonalized is, since this invocation is never the
// normal agent and must never fall through to normal startup.
func runScreenHelperIfRequested() bool {
	if len(os.Args) < 2 || os.Args[1] != screen.PortalHelperFlag {
		return false
	}
	os.Exit(screen.RunPortalHelper(os.Args[2:]))
	return true
}
