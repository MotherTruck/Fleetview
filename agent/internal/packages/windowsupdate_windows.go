package packages

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"fleetview-agent/internal/model"
)

// windowsUpdateSearchScript uses the Windows Update Agent COM API, which
// ships with Windows and needs no extra module (unlike PSWindowsUpdate),
// to list not-yet-installed, non-hidden software updates. -InputObject
// (rather than piping) avoids PowerShell's well-known ConvertTo-Json quirk
// of unwrapping a single-element array into a bare object.
const windowsUpdateSearchScript = `
$ErrorActionPreference = "Stop"
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
$updates = foreach ($u in $result.Updates) {
    $kb = ""
    if ($u.KBArticleIDs.Count -gt 0) { $kb = "KB" + $u.KBArticleIDs[0] }
    [PSCustomObject]@{
        Title    = $u.Title
        KB       = $kb
        Severity = $u.MsrcSeverity
    }
}
ConvertTo-Json -InputObject @($updates) -Compress -Depth 3
`

// windowsUpdateSearch reports pending OS-level security/software updates,
// the gap winget itself doesn't cover (it only sees its own managed apps).
// This is the least-verified piece of the Windows agent: it depends on a
// COM API that can take anywhere from seconds to minutes to respond
// depending on Windows Update's local cache and network reachability, and
// has not been run against a real Windows install. Errors here are meant to
// be non-fatal to the caller (winget's own results should still be usable),
// so failures are returned rather than logged internally.
func windowsUpdateSearch(ctx context.Context) ([]model.Update, error) {
	scriptFile, err := os.CreateTemp("", "fleetview-agent-wu-*.ps1")
	if err != nil {
		return nil, fmt.Errorf("create temporary script: %w", err)
	}
	defer os.Remove(scriptFile.Name())
	if _, err := scriptFile.WriteString(windowsUpdateSearchScript); err != nil {
		scriptFile.Close()
		return nil, fmt.Errorf("write temporary script: %w", err)
	}
	if err := scriptFile.Close(); err != nil {
		return nil, fmt.Errorf("write temporary script: %w", err)
	}

	command := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptFile.Name())
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("windows update search: %w: %s", err, truncate(string(output), 4096))
	}
	return parseWindowsUpdateSearch(output)
}
