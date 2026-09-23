package packages

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fleetview-agent/internal/model"
)

// windowsUpdateSearchTimeout bounds how long a Windows Update search is
// allowed to run; intentionally generous since the underlying COM search
// (in windowsUpdateSearch, windowsupdate_windows.go) can be slow.
const windowsUpdateSearchTimeout = 5 * time.Minute

type windowsUpdateEntry struct {
	Title    string `json:"Title"`
	KB       string `json:"KB"`
	Severity string `json:"Severity"`
}

// parseWindowsUpdateSearch parses the JSON produced by
// windowsUpdateSearchScript. PowerShell's ConvertTo-Json unwraps a
// single-element array into a bare object unless -InputObject is used to
// prevent it, so this tolerates both shapes regardless of which one the
// script actually produces.
func parseWindowsUpdateSearch(output []byte) ([]model.Update, error) {
	trimmed := bytes.TrimSpace(output)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return []model.Update{}, nil
	}

	var entries []windowsUpdateEntry
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &entries); err != nil {
			return nil, fmt.Errorf("parse windows update search output: %w", err)
		}
	} else {
		var single windowsUpdateEntry
		if err := json.Unmarshal(trimmed, &single); err != nil {
			return nil, fmt.Errorf("parse windows update search output: %w", err)
		}
		if strings.TrimSpace(single.Title) != "" {
			entries = append(entries, single)
		}
	}

	result := make([]model.Update, 0, len(entries))
	for _, entry := range entries {
		if strings.TrimSpace(entry.Title) == "" {
			continue
		}
		packageName := "Windows Update: " + entry.Title
		if entry.KB != "" {
			packageName += " (" + entry.KB + ")"
		}
		security := entry.Severity != ""
		rebootLikely := true
		result = append(result, model.Update{
			Package:          packageName,
			AvailableVersion: entry.KB,
			SecurityUpdate:   &security,
			RebootRequired:   &rebootLikely,
		})
	}
	return result, nil
}
