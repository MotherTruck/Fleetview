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

# If this server is reached over HTTPS with a private CA (the project's
# optional Caddy tls profile -- see docs/TLS.md), fetch that CA once over
# an unverified connection and use it for verified validation from then on,
# the same trust-on-first-use bootstrap the Linux installer uses. A server
# on plain HTTP, or behind a real publicly-trusted certificate, needs none
# of this and $caFile simply stays empty.
$caFile = ""
if ($ServerUrl -like "https://*") {
    $caCandidate = Join-Path $programData "ca.crt"
    $originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    $fetched = $false
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        # -OutFile writes the raw response body straight to disk, avoiding
        # Invoke-WebRequest's .Content property, which can come back as a
        # String instead of byte[] depending on the response's Content-Type
        # header -- casting a String to [byte[]] would reinterpret UTF-16
        # char codes rather than the actual certificate bytes.
        Invoke-WebRequest -Uri "$ServerUrl/install/ca.crt" -OutFile $caCandidate -UseBasicParsing -TimeoutSec 15
        $fetched = $true
    } catch {
        $fetched = $false
    } finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
    }
    if ($fetched) {
        try {
            [void][System.Security.Cryptography.X509Certificates.X509Certificate2]::new($caCandidate)
            $caFile = $caCandidate
        } catch {
            # Not a valid certificate -- proceed without pinning one.
            Remove-Item -Path $caCandidate -Force -ErrorAction SilentlyContinue
        }
    }
}

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
if ($caFile) {
    $configLines += "FLEETVIEW_CA_FILE=$caFile"
}
$configPath = Join-Path $programData "agent.env"
Set-Content -Path $configPath -Value $configLines -Encoding ascii

& $exePath -service install -config $configPath
if ($LASTEXITCODE -ne 0) { throw "service install failed with exit code $LASTEXITCODE" }

Write-Host "Agent installed. Follow it with: Get-Content `"$programData\agent.log`" -Tail 50 -Wait"
