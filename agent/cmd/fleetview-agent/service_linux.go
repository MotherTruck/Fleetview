package main

import (
	"fmt"
	"log"
)

func defaultConfigPath() string { return "/etc/fleetview-agent/agent.env" }

// runAsServiceIfHosted always reports false on Linux: the agent is hosted by
// systemd (see agent/packaging/fleetview-agent.service and scripts/install-agent.sh),
// which just runs the plain binary directly rather than requiring any
// in-process service-manager integration the way Windows does.
func runAsServiceIfHosted(logger *log.Logger, configPath string) (handled bool, err error) {
	return false, nil
}

func controlService(action, configPath, uninstallCode string) error {
	return fmt.Errorf("-service %q is only supported on Windows; on Linux use systemd (see scripts/install-agent.sh and scripts/uninstall-agent.sh)", action)
}
