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

// Winget only covers winget-managed applications, not Windows' own OS-level
// security patches (Windows Update); that is a separate, not-yet-implemented
// data source. This parser has not been verified against a real winget
// install (there is no Windows environment available to test against) and
// assumes an English-language console: winget's table headers are localized,
// so a non-English Windows install will fail to parse until this is widened.
type Winget struct{}

func (Winget) Name() string { return "winget" }

func (Winget) Installed(ctx context.Context) ([]model.Package, error) {
	output, err := exec.CommandContext(ctx, "winget", "list", "--accept-source-agreements").Output()
	if err != nil {
		return nil, fmt.Errorf("winget list: %w", err)
	}
	rows := parseWingetTable(string(output), []string{"Name", "Id", "Version", "Source"})
	result := []model.Package{}
	for _, row := range rows {
		id := row["Id"]
		if id == "" {
			continue
		}
		result = append(result, model.Package{
			Name:    firstNonEmptyValue(row["Name"], id),
			Version: row["Version"],
			Source:  "winget",
		})
	}
	return result, nil
}

func (Winget) Updates(ctx context.Context) ([]model.Update, error) {
	output, err := exec.CommandContext(ctx, "winget", "upgrade", "--accept-source-agreements").CombinedOutput()
	rows := parseWingetTable(string(output), []string{"Name", "Id", "Version", "Available", "Source"})
	if rows == nil && err != nil {
		return nil, fmt.Errorf("winget upgrade: %w: %s", err, strings.TrimSpace(string(output)))
	}
	result := []model.Update{}
	for _, row := range rows {
		id := row["Id"]
		if id == "" {
			continue
		}
		result = append(result, model.Update{
			Package:          firstNonEmptyValue(row["Name"], id),
			Identifier:       id,
			InstalledVersion: row["Version"],
			AvailableVersion: row["Available"],
		})
	}

	// winget only sees its own managed apps, not Windows' own OS-level
	// security patches, so those are merged in from a separate search. This
	// step is best-effort: its failure doesn't invalidate the winget results
	// already collected above.
	osCtx, cancel := context.WithTimeout(ctx, windowsUpdateSearchTimeout)
	defer cancel()
	if osUpdates, osErr := windowsUpdateSearch(osCtx); osErr == nil {
		result = append(result, osUpdates...)
	}
	return result, nil
}

func (Winget) InstallUpdates() (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	output, err := exec.CommandContext(ctx, "winget", "upgrade", "--all",
		"--accept-source-agreements", "--accept-package-agreements", "--silent", "--disable-interactivity").CombinedOutput()
	exitCode := 0
	if err != nil {
		exitCode = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		if ctx.Err() == context.DeadlineExceeded {
			err = fmt.Errorf("update timed out after two hours")
		}
	}
	return truncate(string(output), 1_048_576), exitCode, err
}

func (Winget) Install(parent context.Context, packageName string) (string, int, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Minute)
	defer cancel()
	output, err := exec.CommandContext(ctx, "winget", "install", "--id", packageName,
		"--accept-source-agreements", "--accept-package-agreements", "--silent", "--disable-interactivity").CombinedOutput()
	exitCode := 0
	if err != nil {
		exitCode = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		if ctx.Err() == context.DeadlineExceeded {
			err = fmt.Errorf("install timed out after 30 minutes")
		}
	}
	return truncate(string(output), 1_048_576), exitCode, err
}
