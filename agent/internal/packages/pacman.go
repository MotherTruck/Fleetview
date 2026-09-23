package packages

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"fleetview-agent/internal/model"
)

type Pacman struct{}

func (Pacman) Name() string { return "pacman" }

func (Pacman) Installed(ctx context.Context) ([]model.Package, error) {
	output, err := exec.CommandContext(ctx, "pacman", "-Q").Output()
	if err != nil { return nil, fmt.Errorf("pacman -Q: %w", err) }
	result := []model.Package{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			result = append(result, model.Package{Name: fields[0], Version: strings.Join(fields[1:], " "), Source: "pacman"})
		}
	}
	return result, nil
}

func (Pacman) Updates(ctx context.Context) ([]model.Update, error) {
	command := exec.CommandContext(ctx, "checkupdates")
	output, err := command.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 2 { return []model.Update{}, nil }
		return nil, fmt.Errorf("checkupdates: %w: %s", err, strings.TrimSpace(string(output)))
	}
	result := []model.Update{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[2] == "->" {
			result = append(result, model.Update{Package: fields[0], InstalledVersion: fields[1], AvailableVersion: fields[3]})
		}
	}
	return result, nil
}

func (Pacman) InstallUpdates() (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	output, err := exec.CommandContext(ctx, "pacman", "-Syu", "--noconfirm").CombinedOutput()
	exitCode := 0
	if err != nil {
		exitCode = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) { exitCode = exitErr.ExitCode() }
		if ctx.Err() == context.DeadlineExceeded { err = fmt.Errorf("update timed out after two hours") }
	}
	return truncate(string(output), 1_048_576), exitCode, err
}

func (Pacman) Install(parent context.Context, packageName string) (string, int, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Minute)
	defer cancel()
	output, err := exec.CommandContext(ctx, "pacman", "-Sy", "--noconfirm", "--needed", packageName).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("install timed out after 30 minutes")
	}
	return truncate(string(output), 1_048_576), exitCode(err), err
}
