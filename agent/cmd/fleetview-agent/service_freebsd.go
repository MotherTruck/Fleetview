//go:build freebsd

package main

import (
	"fmt"
	"log"
)

func defaultConfigPath() string { return "/usr/local/etc/fleetview-agent/agent.env" }

// runAsServiceIfHosted always reports false on FreeBSD: the agent is
// hosted by rc.d (see agent/packaging/fleetview-agent.rc and
// scripts/install-agent-opnsense.sh), which just runs the plain binary
// directly, the same as systemd does on Linux -- no in-process service-
// manager integration needed.
func runAsServiceIfHosted(logger *log.Logger, configPath string) (handled bool, err error) {
	return false, nil
}

func controlService(action, configPath, uninstallCode string, force bool) error {
	return fmt.Errorf("-service %q is only supported on Windows; on FreeBSD/OPNsense use service(8) (see scripts/install-agent-opnsense.sh and scripts/uninstall-agent.sh)", action)
}

// finishUpgrade only exists on Windows; see service_linux.go's identical
// comment -- applyUpgrade (upgrade_freebsd.go) replaces the binary and
// re-execs in a single step here too.
func finishUpgrade(targetPath string) error {
	return fmt.Errorf("-finish-upgrade is only used internally on Windows")
}
