//go:build freebsd

package main

import "log"

// ensureRemoteControlDependencies is a no-op on FreeBSD: screen.Detect()
// (screen_freebsd.go) always reports remote control unavailable on this
// platform, so there's nothing to install.
func ensureRemoteControlDependencies(*log.Logger) {}
