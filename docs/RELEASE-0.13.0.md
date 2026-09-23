# FleetView 0.13.0 — accounts and complete color themes

## What changed

- Green, blue, purple, amber and pink each have a coordinated dark background,
  surfaces, borders, readable text, and a lighter accent. Semantic warning,
  failure and success colors remain recognizable. Themes stay per browser.
- Username/password login replaces routine admin-token login. First setup
  requires the existing ADMIN_TOKEN once to create the initial administrator.
  Afterwards X-Admin-Token cannot bypass account permissions.
- Admin → User management creates users, assigns roles, enables/disables
  accounts and sets temporary passwords. Temporary passwords must be changed
  on first sign-in. There is no public self-registration.
- Viewer: read fleet inventory, monitoring, jobs, catalog and reports.
  Operator: those reads plus scan/patch/package jobs, catalog edits and scan
  schedules. Admin: all operations, enrollment, device removal/settings,
  fleet defaults, users and account audit history. Roles are fleet-wide;
  per-device/group ACLs, SSO and MFA are not implemented.
- Changing passwords, resetting accounts, disabling users, or changing roles
  revokes their sessions. The last enabled admin cannot be disabled/demoted.
- Sessions expire after 12 hours and survive ordinary server restarts.
  HttpOnly/SameSite cookies, CSRF tokens, login attempt throttling, salted
  PBKDF2-SHA256 hashes and account-change audit records are included.

## Upgrade your current installation

Keep /containers/epc-replacement, the current Compose file, .env, PostgreSQL
volume and epc-agent service. This release changes only the server; no agent
re-enrollment or native-agent upgrade is required for these features.
The source bundle still contains the 0.12.0 agent for previous uninstall work.

After downloading FleetView-0.13.0.zip to Downloads, run in Bash:

```bash
set -e
release_dir=$(mktemp -d)
unzip -q "$HOME/Downloads/FleetView-0.13.0.zip" -d "$release_dir"
bash "$release_dir/Endpoint-Central-replacement-claude-epc-replacement-continue-v8o0cx/scripts/upgrade-server-in-place.sh" /containers/epc-replacement
```

The script backs up the live database and current source/config, preserves the
existing Compose configuration, builds the server, and replaces only that
container. A live backup is appropriate for an upgrade but is NOT a migration
cutover snapshot: use VM-MIGRATION.md for that.

Refresh the dashboard. Enter the existing admin token once and choose your
username/password (12–128 characters). Add users under Admin. Keep .env:
Compose may still require ADMIN_TOKEN, even though it no longer authorizes
dashboard/API access after setup. Database additions are new tables only.

The app supports current LAN HTTP use; deploy it behind HTTPS for ongoing
password use. Secure cookies are automatic when the app sees HTTPS. When
Traefik terminates TLS and forwards HTTP, set FLEETVIEW_COOKIE_SECURE: "true"
in the server service's Compose environment, then recreate the server. This
variable must be passed to the container; adding only a .env line is not enough.
Do not set it while accessing the dashboard directly over ordinary LAN HTTP.

## Local admin recovery

Use the server console if the admin password is lost (password prompts are
hidden, and the command revokes existing sessions):

```bash
cd /containers/epc-replacement
sudo docker compose exec server python -m app.manage_users YOUR_ADMIN_USERNAME
```

This only resets an existing admin. It does not create a remote token bypass.

## Validation and limits

The 44 server tests and the dashboard DOM test passed. An actual Chromium
run covered first-admin setup, all five themes, viewer provisioning, forced
password change, and session persistence. See server/tests/test_accounts.py
for setup, CSRF, role enforcement, invalidation, expiry, throttling, duplicate
users and last-admin checks. SQLite API tests
do not establish PostgreSQL concurrency guarantees; test the VM restore and
account access there before moving endpoint traffic. Migration instructions
were prepared, not executed on your network.

Security references:
- https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
