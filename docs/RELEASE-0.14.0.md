# FleetView 0.14.0 — uploaded installers, patch approvals and schedules

## Upgrade the current test machine

Keep `/containers/epc-replacement` and its Compose file, `.env`, PostgreSQL
volume, `/etc/epc-agent/agent.env` and `/var/lib/epc-agent/state.json`.
Do not run the new-install Compose file from this ZIP. New tables are additive.

Place FleetView-0.14.0.zip in `~/Downloads`. In Bash (the one-line outer
`bash -c` wrapper also works from Fish):

```bash
bash -c '
set -e
release_dir="$(mktemp -d)"
unzip -q "$HOME/Downloads/FleetView-0.14.0.zip" -d "$release_dir"
bash "$release_dir/Endpoint-Central-replacement-claude-epc-replacement-continue-v8o0cx/scripts/upgrade-server-in-place.sh" /containers/epc-replacement
bash /containers/epc-replacement/scripts/upgrade-agent-in-place.sh
'
```

The first script writes a private database and source/config backup under
`~/epc-server-backup-*`, rebuilds only the existing server, and leaves DB and
agents in place. The second requires Go on that machine and replaces its
existing native agent binary, preserving the service name/config/state and
copying the previous binary into your home directory. No enrollment token is
needed. Repeat the native agent step on every remote Linux endpoint after
extracting the release ZIP there, using its extracted `scripts/upgrade-agent-in-place.sh`.
For existing Windows endpoints, run the new `scripts/upgrade-agent-in-place.ps1`
from the extracted ZIP as Administrator. It builds a new binary, restarts the
existing Windows service and retains its config and state. Do not run the
fresh-install script on an already enrolled endpoint.

Check on the server:

```bash
cd /containers/epc-replacement
sudo docker compose ps
curl -fsS http://127.0.0.1:8080/healthz
sudo systemctl status epc-agent --no-pager -l
```

If an agent is still at 0.12.0 or older, ordinary inventory remains available.
The server refuses to queue new patch/custom installer jobs until the agent
reports version 0.14.0; run Patch scan after restarting the agent to refresh
its version. The previous unrestricted Install updates API action is disabled.

## Using the new controls

Open Patching → Review on a device, approve the needed version(s), then choose
Deploy approved patches. A new version starts unapproved; revoked approvals
will be excluded from future jobs. To automate, save an interval in hours on
that same device. Zero disables it. Due jobs queue at the next agent check-in;
missed periods collapse and an active patch job blocks a duplicate. Schedules
select the approved versions that are pending when they fire, then the agent
checks the same versions again before installing. Queued jobs are snapshots:
revoking an approval cancels matching pending jobs, but cannot stop an agent
that has already claimed one.

On Arch, **all** pending packages must be approved because pacman partial
upgrades are unsupported. Debian simulates `apt-get install --only-upgrade`
for the approved exact versions first and refuses a transaction that upgrades
any other package. Winget uses its package IDs and exact versions; Windows OS
updates without winget IDs remain visible but cannot be approved/deployed here.

Under Deploy → Upload an installer, admins can supply one to five files
(maximum 8 MiB per file, 16 MiB combined), target OS, and command. Each saved
bundle is immutable. Select matching devices, review the exact command and
file list in the confirmation, then deploy. Linux runs the command with Bash;
Windows uses PowerShell. The agent downloads files into a private temporary
directory, checks size/SHA-256, executes from there, and removes the files.
Only administrators can upload or deploy custom bundles because agent service
privileges allow system changes. Back up PostgreSQL regularly: custom files
are stored alongside inventory and authentication data.

## Verification

48 isolated server tests, Linux Go tests, a Windows cross-build, dashboard DOM
tests, and a real Chromium workflow for approval, schedule, upload and job
queueing passed. Debian package transactions and actual Windows installers
were not run on endpoints here. Start with a small test package and inspect
the job result before deploying broadly.
