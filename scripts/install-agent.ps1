#requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the FleetView agent as a Windows service.
.DESCRIPTION
    Downloads the agent binary the management server already cross-compiles
    and publishes at build time (see server/Dockerfile's agent-build stage,
    and the same /install/agent-version manifest + /install/agent-windows-
    amd64.exe the dashboard's remote "Upgrade agent" job already uses) and
    verifies its SHA-256 against that manifest before installing anything --
    the same check agent/cmd/fleetview-agent/upgrade.go performs for an
    in-place upgrade. No local Go toolchain is needed on the endpoint.
.PARAMETER ServerUrl
    The management server's base URL, e.g. http://192.168.1.50:8080
.PARAMETER EnrollmentToken
    The one-time token from the dashboard's Agent -> Add a new device page.
.PARAMETER CaFingerprint
    Optional SHA-256 fingerprint of the server's private CA (see
    docs/TLS.md). When set, the CA fetched from /install/ca.crt is verified
    against it before being trusted -- and, unlike before, that trust now
    also covers the manifest and binary downloads below, not just the CA
    file itself. Omit it to keep the default TOFU behavior.
#>
param(
    [Parameter(Mandatory = $true)][string]$ServerUrl,
    [Parameter(Mandatory = $true)][string]$EnrollmentToken,
    [string]$CaFingerprint = ""
)

# Normalize to bare uppercase hex so it matches regardless of how the admin
# copied it -- openssl prints it colon-separated, browsers often don't.
$CaFingerprint = ($CaFingerprint -replace '[:\s]', '').ToUpperInvariant()

$ErrorActionPreference = "Stop"
$ServerUrl = $ServerUrl.TrimEnd('/')

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Error "Missing dependency: winget. Install 'App Installer' from the Microsoft Store before continuing."
    exit 1
}

$programData = Join-Path $env:ProgramData "fleetview-agent"
New-Item -ItemType Directory -Force -Path $programData | Out-Null

# If this server is reached over HTTPS with a private CA (the project's
# optional Caddy tls profile -- see docs/TLS.md), fetch that CA once over
# an unverified connection and use it for verified validation from then on,
# the same trust-on-first-use bootstrap the Linux installer uses. A server
# on plain HTTP, or behind a real publicly-trusted certificate, needs none
# of this and $caFile simply stays empty. Passing -CaFingerprint closes
# that TOFU gap: the fetched CA is verified against a fingerprint the admin
# already obtained out-of-band before anything is trusted.
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
        # Parsing failure and a fingerprint mismatch are deliberately NOT
        # both handled inside one try/catch: under $ErrorActionPreference =
        # "Stop", Write-Error itself throws a terminating error, so a
        # Write-Error for a genuine mismatch issued *inside* that try block
        # would immediately be swallowed by its own catch and reported as
        # the wrong, more generic failure -- masking what's actually a
        # detected CA substitution as a mere fetch failure.
        $candidateCert = $null
        try {
            $candidateCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($caCandidate)
        } catch {
            $candidateCert = $null
        }
        if (-not $candidateCert) {
            # Not a valid certificate -- proceed without pinning one, unless
            # the admin explicitly asked for fingerprint verification, in
            # which case silently falling back to TOFU would defeat the point.
            Remove-Item -Path $caCandidate -Force -ErrorAction SilentlyContinue
            if ($CaFingerprint) {
                Write-Error "Could not fetch a valid CA from $ServerUrl/install/ca.crt to verify against the pinned fingerprint; refusing to install without it."
                exit 1
            }
        } elseif ($CaFingerprint -and $candidateCert.GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::SHA256) -ne $CaFingerprint) {
            $actualFingerprint = $candidateCert.GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::SHA256)
            Remove-Item -Path $caCandidate -Force -ErrorAction SilentlyContinue
            Write-Error "CA fingerprint mismatch (expected $CaFingerprint, got $actualFingerprint); refusing to trust it. This means either the pinned fingerprint is wrong, or something on the network path substituted a different CA."
            exit 1
        } else {
            $caFile = $caCandidate
        }
    } elseif ($CaFingerprint) {
        Write-Error "Could not fetch a valid CA from $ServerUrl/install/ca.crt to verify against the pinned fingerprint; refusing to install without it."
        exit 1
    }
}

# Download the published agent binary and verify it, with the CA pinned
# above (if any) actually enforced for these requests -- not just the one
# bootstrap fetch. .NET has no curl --cacert equivalent to trust a single
# extra root for one request, so the pinned CA is installed into the
# CurrentUser\Root store for just this block (removed in `finally` either
# way) rather than left unverified: this session already trusts it (via
# fingerprint or TOFU above), so the only question is whether these HTTP
# requests actually get that verification, not whether to grant it.
$tempTrustCert = $null
try {
    if ($caFile) {
        $tempTrustCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($caFile)
        $rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new("Root", "CurrentUser")
        $rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        try { $rootStore.Add($tempTrustCert) } finally { $rootStore.Close() }
    }

    # -OutFile + Get-Content, not .Content: Invoke-WebRequest returns .Content
    # as a raw byte[] rather than a decoded string for some content-types,
    # same hazard the ca.crt fetch above avoids the same way.
    $manifestPath = Join-Path $programData "agent-manifest.json"
    Invoke-WebRequest -Uri "$ServerUrl/install/agent-version" -OutFile $manifestPath -UseBasicParsing -TimeoutSec 30
    $manifest = Get-Content -Raw -Path $manifestPath | ConvertFrom-Json
    Remove-Item -Path $manifestPath -Force -ErrorAction SilentlyContinue
    $asset = $manifest.windows_amd64
    if (-not $asset -or -not $asset.sha256 -or -not $asset.path) {
        throw "Server did not publish a Windows agent binary manifest at $ServerUrl/install/agent-version."
    }

    $downloadedExe = Join-Path $programData "fleetview-agent-download.exe"
    Invoke-WebRequest -Uri "$ServerUrl$($asset.path)" -OutFile $downloadedExe -UseBasicParsing -TimeoutSec 120

    # Same check agent/cmd/fleetview-agent/upgrade.go's stageUpgrade performs
    # before an in-place upgrade is allowed to apply.
    $actualSha = (Get-FileHash -Path $downloadedExe -Algorithm SHA256).Hash
    if ($actualSha.ToUpperInvariant() -ne $asset.sha256.ToUpperInvariant()) {
        Remove-Item -Path $downloadedExe -Force -ErrorAction SilentlyContinue
        throw "Downloaded agent binary checksum mismatch (expected $($asset.sha256), got $actualSha); refusing to install."
    }
} finally {
    if ($tempTrustCert) {
        $rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new("Root", "CurrentUser")
        $rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        try { $rootStore.Remove($tempTrustCert) } finally { $rootStore.Close() }
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

# -service install copies $downloadedExe into %ProgramFiles%\FleetView
# Agent\fleetview-agent.exe itself and registers the service pointing
# there (see agent/cmd/fleetview-agent/service_windows.go's installService)
# -- it doesn't need to already live there.
& $downloadedExe -service install -config $configPath
if ($LASTEXITCODE -ne 0) { throw "service install failed with exit code $LASTEXITCODE" }
Remove-Item -Path $downloadedExe -Force -ErrorAction SilentlyContinue

Write-Host "Agent installed. Follow it with: Get-Content `"$programData\agent.log`" -Tail 50 -Wait"
