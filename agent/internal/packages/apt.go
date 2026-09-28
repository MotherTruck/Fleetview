package packages

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"fleetview-agent/internal/model"
)

type APT struct{}

var aptUpgradePattern = regexp.MustCompile(`^([^/]+)/\S+\s+(\S+)\s+(\S+)\s+\[upgradable from:\s*([^\]]+)\]`)

func (APT) Name() string { return "apt" }

func (APT) Installed(ctx context.Context) ([]model.Package, error) {
	output, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\n").Output()
	if err != nil {
		return nil, fmt.Errorf("dpkg-query: %w", err)
	}
	result := []model.Package{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) >= 3 {
			result = append(result, model.Package{Name: fields[0], Version: fields[1], Architecture: fields[2], Source: "apt"})
		}
	}
	return result, nil
}

func (APT) Updates(ctx context.Context) ([]model.Update, error) {
	updateCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	updateOutput, err := exec.CommandContext(updateCtx, "apt-get", "update").CombinedOutput()
	if err != nil {
		if updateCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("apt-get update timed out after 5 minutes")
		}
		return nil, fmt.Errorf("apt-get update: %w: %s", err, strings.TrimSpace(string(updateOutput)))
	}
	command := exec.CommandContext(ctx, "apt", "list", "--upgradable")
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("apt list --upgradable: %w: %s", err, strings.TrimSpace(string(output)))
	}
	rebootRequired := false
	if _, statErr := os.Stat("/var/run/reboot-required"); statErr == nil {
		rebootRequired = true
	}
	result := []model.Update{}
	for _, line := range strings.Split(string(output), "\n") {
		match := aptUpgradePattern.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) != 5 {
			continue
		}
		security := strings.Contains(strings.ToLower(line), "security")
		securityValue := security
		rebootValue := rebootRequired
		result = append(result, model.Update{
			Package: match[1], InstalledVersion: match[4], AvailableVersion: match[2],
			SecurityUpdate: &securityValue, RebootRequired: &rebootValue,
		})
	}
	return result, nil
}

func (APT) InstallUpdates() (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	updateOutput, updateErr := exec.CommandContext(ctx, "apt-get", "update").CombinedOutput()
	if updateErr != nil {
		return truncate(string(updateOutput), 1_048_576), exitCode(updateErr), updateErr
	}
	command := exec.CommandContext(ctx, "apt-get", "-y", "upgrade")
	command.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	upgradeOutput, err := command.CombinedOutput()
	output := append(updateOutput, upgradeOutput...)
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("update timed out after two hours")
	}
	return truncate(string(output), 1_048_576), exitCode(err), err
}

func (APT) Install(parent context.Context, packageName string) (string, int, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Minute)
	defer cancel()
	updateOutput, updateErr := exec.CommandContext(ctx, "apt-get", "update").CombinedOutput()
	if updateErr != nil {
		return truncate(string(updateOutput), 1_048_576), exitCode(updateErr), updateErr
	}
	command := exec.CommandContext(ctx, "apt-get", "-y", "install", "--", packageName)
	command.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	installOutput, err := command.CombinedOutput()
	output := append(updateOutput, installOutput...)
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("install timed out after 30 minutes")
	}
	return truncate(string(output), 1_048_576), exitCode(err), err
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}
