package packages

import (
	"context"
	"errors"
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

// FetchWindowsUpdateEntries runs the Windows Update Agent COM API search
// and returns its raw entries. It's independent of winget -- both
// Winget.Updates (merging OS patches into winget's own update list) and the
// Windows vulnerability scanner (internal/vulnerability, consulted whether
// or not winget is present) call this directly rather than going through a
// winget-specific path.
//
// This is the least-verified piece of the Windows agent: it depends on a
// COM API that can take anywhere from seconds to minutes to respond
// depending on Windows Update's local cache and network reachability, and
// has not been run against a real Windows install. Errors here are meant to
// be non-fatal to a caller that has other data to fall back on (see
// Winget.Updates), so failures are returned rather than logged internally.
func FetchWindowsUpdateEntries(ctx context.Context) ([]WindowsUpdateEntry, error) {
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
	return parseWindowsUpdateEntries(output)
}

// windowsUpdateSearch reports pending OS-level security/software updates as
// model.Update values, the gap winget itself doesn't cover (it only sees
// its own managed apps).
func windowsUpdateSearch(ctx context.Context) ([]model.Update, error) {
	entries, err := FetchWindowsUpdateEntries(ctx)
	if err != nil {
		return nil, err
	}
	return entriesToUpdates(entries), nil
}

// windowsUpdateInstallScript searches for, downloads, and installs pending
// updates via the same Windows Update Agent COM API used for the search
// above. ResultCode 2 is "Succeeded" and 3 is "SucceededWithErrors" (the
// WUA OperationResultCode enum); both are treated as install success here
// since SucceededWithErrors still means some updates went in.
const windowsUpdateInstallScript = `
$ErrorActionPreference = "Stop"
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
if ($result.Updates.Count -eq 0) {
    Write-Output "No updates to install."
    exit 0
}
$toDownload = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $result.Updates) { $toDownload.Add($u) | Out-Null }
$downloader = $session.CreateUpdateDownloader()
$downloader.Updates = $toDownload
$downloadResult = $downloader.Download()
Write-Output "DownloadResultCode=$($downloadResult.ResultCode)"
if ($downloadResult.ResultCode -ne 2 -and $downloadResult.ResultCode -ne 3) {
    Write-Error "Download failed with result code $($downloadResult.ResultCode)"
    exit 1
}
$toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $result.Updates) { if ($u.IsDownloaded) { $toInstall.Add($u) | Out-Null } }
$installer = $session.CreateUpdateInstaller()
$installer.Updates = $toInstall
$installResult = $installer.Install()
Write-Output "InstallResultCode=$($installResult.ResultCode) RebootRequired=$($installResult.RebootRequired)"
if ($installResult.ResultCode -ne 2 -and $installResult.ResultCode -ne 3) {
    exit 1
}
exit 0
`

// installWindowsUpdates runs windowsUpdateInstallScript, mirroring the
// (output, exitCode, error) convention Winget.InstallUpdates and
// Winget.Install already use.
func installWindowsUpdates(ctx context.Context) (string, int, error) {
	scriptFile, err := os.CreateTemp("", "fleetview-agent-wu-install-*.ps1")
	if err != nil {
		return "", -1, fmt.Errorf("create temporary script: %w", err)
	}
	defer os.Remove(scriptFile.Name())
	if _, err := scriptFile.WriteString(windowsUpdateInstallScript); err != nil {
		scriptFile.Close()
		return "", -1, fmt.Errorf("write temporary script: %w", err)
	}
	if err := scriptFile.Close(); err != nil {
		return "", -1, fmt.Errorf("write temporary script: %w", err)
	}

	command := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptFile.Name())
	output, err := command.CombinedOutput()
	exitCode := 0
	if err != nil {
		exitCode = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		if ctx.Err() == context.DeadlineExceeded {
			err = fmt.Errorf("windows update install timed out")
		}
	}
	return truncate(string(output), 1_048_576), exitCode, err
}
