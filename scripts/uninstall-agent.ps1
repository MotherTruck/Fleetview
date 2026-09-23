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
#>
param(
    [string]$Code = ""
)

$ErrorActionPreference = "Stop"

$exePath = Join-Path $env:ProgramFiles "FleetView Agent\fleetview-agent.exe"
if (-not (Test-Path $exePath)) {
    Write-Error "Could not find an installed agent at $exePath"
    exit 1
}

if ($Code -ne "") {
    & $exePath -service uninstall -uninstall-code $Code
} else {
    & $exePath -service uninstall
}
exit $LASTEXITCODE
