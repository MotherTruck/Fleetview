#requires -RunAsAdministrator
<#
.SYNOPSIS
    Removes the FleetView agent Windows service.
.DESCRIPTION
    Windows counterpart to scripts/uninstall-agent.sh. All of the actual
    work (verifying the managed-uninstall code with the server, stopping and
    deleting the service, removing the installed files) lives in the agent
    binary itself as `fleetview-agent.exe -service uninstall`; this script
    just finds that binary so the command is as memorable as the Linux one.
.PARAMETER Code
    The managed-uninstall code, if one is configured. Omit to be prompted.
.PARAMETER Force
    Remove the agent even if the server can't be reached to verify the
    uninstall code -- for a device that's stopped communicating entirely
    (down link, stale credentials after a server migration, etc.) and would
    otherwise have no supported way to be removed. This does NOT bypass a
    code the server is reachable and actively rejects.
#>
param(
    [string]$Code = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$exePath = Join-Path $env:ProgramFiles "FleetView Agent\fleetview-agent.exe"
if (-not (Test-Path $exePath)) {
    Write-Error "Could not find an installed agent at $exePath"
    exit 1
}

$exeArgs = @("-service", "uninstall")
if ($Code -ne "") { $exeArgs += @("-uninstall-code", $Code) }
if ($Force) { $exeArgs += "-force" }
& $exePath @exeArgs
exit $LASTEXITCODE
