#requires -RunAsAdministrator
<#
.SYNOPSIS
    Builds and installs the FleetView agent as a Windows service.
.DESCRIPTION
    Windows counterpart to scripts/install-agent.sh: builds the agent from
    this checkout's Go source, writes its configuration under
    %ProgramData%\fleetview-agent, and registers + starts it as a Windows
    service via `fleetview-agent.exe -service install`.
.PARAMETER ServerUrl
    The management server's base URL, e.g. http://192.168.1.50:8080
.PARAMETER EnrollmentToken
    The one-time token from the dashboard's Agent -> Add a new device page.
#>
param(
    [Parameter(Mandatory = $true)][string]$ServerUrl,
    [Parameter(Mandatory = $true)][string]$EnrollmentToken
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Error "Missing dependency: go. Install Go before continuing."
    exit 1
}
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Error "Missing dependency: winget. Install 'App Installer' from the Microsoft Store before continuing."
    exit 1
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$agentDir = Join-Path $projectRoot "agent"
$binDir = Join-Path $agentDir "bin"
$exePath = Join-Path $binDir "fleetview-agent.exe"

New-Item -ItemType Directory -Force -Path $binDir | Out-Null
Push-Location $agentDir
try {
    & go build -trimpath -ldflags="-s -w" -o $exePath ./cmd/fleetview-agent
    if ($LASTEXITCODE -ne 0) { throw "go build failed with exit code $LASTEXITCODE" }
}
finally {
    Pop-Location
}

$programData = Join-Path $env:ProgramData "fleetview-agent"
New-Item -ItemType Directory -Force -Path $programData | Out-Null

$configLines = @(
    "FLEETVIEW_SERVER_URL=$ServerUrl"
    "FLEETVIEW_ENROLLMENT_TOKEN=$EnrollmentToken"
    "FLEETVIEW_STATE_PATH=$programData\state.json"
    "FLEETVIEW_SCAN_INTERVAL_SECONDS=900"
    "FLEETVIEW_METRICS_INTERVAL_SECONDS=60"
    "FLEETVIEW_JOB_POLL_SECONDS=10"
    "FLEETVIEW_REQUEST_TIMEOUT_SECONDS=60"
    "FLEETVIEW_ALLOW_INSECURE_TLS=false"
)
$configPath = Join-Path $programData "agent.env"
Set-Content -Path $configPath -Value $configLines -Encoding ascii

& $exePath -service install -config $configPath
if ($LASTEXITCODE -ne 0) { throw "service install failed with exit code $LASTEXITCODE" }

Write-Host "Agent installed. Follow it with: Get-Content `"$programData\agent.log`" -Tail 50 -Wait"
