#requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$installDir = Join-Path $env:ProgramFiles 'FleetView Agent'
$exePath = Join-Path $installDir 'fleetview-agent.exe'
$statePath = Join-Path $env:ProgramData 'fleetview-agent\state.json'
$configPath = Join-Path $env:ProgramData 'fleetview-agent\agent.env'
if (!(Test-Path $exePath) -or !(Test-Path $statePath) -or !(Test-Path $configPath)) {
    throw 'An existing enrolled FleetView service and state are required.'
}
if (!(Get-Service -Name 'fleetview-agent' -ErrorAction SilentlyContinue)) {
    throw 'The existing fleetview-agent service was not found.'
}
if (!(Get-Command go -ErrorAction SilentlyContinue)) { throw 'Go is required to build this release.' }
$source = Join-Path (Split-Path -Parent $PSScriptRoot) 'agent'
$temp = Join-Path $env:TEMP ("fleetview-agent-" + [guid]::NewGuid().ToString('N') + '.exe')
Push-Location $source
try {
    & go build -buildvcs=false -trimpath -ldflags='-s -w' -o $temp ./cmd/fleetview-agent
    if ($LASTEXITCODE -ne 0) { throw "Agent build failed ($LASTEXITCODE)." }
} finally { Pop-Location }
$backup = "$exePath.backup-$(Get-Date -Format yyyyMMdd-HHmmss)"
try {
    Stop-Service -Name 'fleetview-agent' -ErrorAction Stop
    Copy-Item $exePath $backup -ErrorAction Stop
    Copy-Item $temp $exePath -Force -ErrorAction Stop
    Start-Service -Name 'fleetview-agent' -ErrorAction Stop
    Get-Service -Name 'fleetview-agent'
    Write-Host "Enrollment preserved. Previous binary: $backup"
} catch {
    if (Test-Path $backup) {
        Copy-Item $backup $exePath -Force
        Start-Service -Name 'fleetview-agent' -ErrorAction SilentlyContinue
    }
    throw
} finally { Remove-Item $temp -ErrorAction SilentlyContinue }
