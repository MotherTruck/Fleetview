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

// WindowsUpdateEntry is one pending update reported by the Windows Update
// Agent COM API search (FetchWindowsUpdateEntries, windowsupdate_windows.go).
// It's exported so both the package-manager Updates() path and the Windows
// vulnerability scanner (internal/vulnerability) can consume the same
// search result without running the COM search twice.
type WindowsUpdateEntry struct {
	Title    string `json:"Title"`
	KB       string `json:"KB"`
	Severity string `json:"Severity"`
}

// parseWindowsUpdateEntries parses the JSON produced by
// windowsUpdateSearchScript into WindowsUpdateEntry values, dropping any
// entry with no title. PowerShell's ConvertTo-Json unwraps a single-element
// array into a bare object unless -InputObject is used to prevent it, so
// this tolerates both shapes regardless of which one the script actually
// produces.
func parseWindowsUpdateEntries(output []byte) ([]WindowsUpdateEntry, error) {
	trimmed := bytes.TrimSpace(output)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return []WindowsUpdateEntry{}, nil
	}

	var entries []WindowsUpdateEntry
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &entries); err != nil {
			return nil, fmt.Errorf("parse windows update search output: %w", err)
		}
	} else {
		var single WindowsUpdateEntry
		if err := json.Unmarshal(trimmed, &single); err != nil {
			return nil, fmt.Errorf("parse windows update search output: %w", err)
		}
		if strings.TrimSpace(single.Title) != "" {
			entries = append(entries, single)
		}
	}

	result := make([]WindowsUpdateEntry, 0, len(entries))
	for _, entry := range entries {
		if strings.TrimSpace(entry.Title) == "" {
			continue
		}
		result = append(result, entry)
	}
	return result, nil
}

// entriesToUpdates adapts WindowsUpdateEntry values into model.Update
// values for Winget.Updates's merged update list.
func entriesToUpdates(entries []WindowsUpdateEntry) []model.Update {
	result := make([]model.Update, 0, len(entries))
	for _, entry := range entries {
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
	return result
}

// parseWindowsUpdateSearch parses the JSON produced by
// windowsUpdateSearchScript directly into model.Update values.
func parseWindowsUpdateSearch(output []byte) ([]model.Update, error) {
	entries, err := parseWindowsUpdateEntries(output)
	if err != nil {
		return nil, err
	}
	return entriesToUpdates(entries), nil
}
