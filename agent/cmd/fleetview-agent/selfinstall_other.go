//go:build !windows

package main

// runSelfInstallIfPersonalized is a Windows-only feature (see
// selfinstall_windows.go): a personalized, download-and-double-click
// installer only makes sense for a Windows service install. Always
// false elsewhere so main's dispatch is unaffected.
func runSelfInstallIfPersonalized() bool { return false }
