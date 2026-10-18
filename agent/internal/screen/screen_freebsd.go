package screen

import "fmt"

// Detect always reports unavailable on FreeBSD: this agent targets
// OPNsense, a headless firewall appliance with no graphical session to
// capture. The dashboard's "Remote control" button for a FreeBSD device
// doesn't call through to this package at all -- it opens the device's
// own web GUI in a new tab instead (see app.js's screen-tab click
// handler) -- but Detect/NewSession still need a real implementation so
// inventory.Collect (which reports this capability either way) and the
// rest of the agent build for this platform.
func Detect() Capability {
	return Capability{
		Available: false,
		Reason:    "FreeBSD/OPNsense has no graphical session to capture -- use the device's own web GUI or the terminal instead",
	}
}

func NewSession() (Session, error) {
	return nil, fmt.Errorf("remote control is not available on FreeBSD/OPNsense")
}
