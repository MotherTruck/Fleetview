# Agent protocol (v1)

All agent calls use JSON over HTTP(S). After enrollment, requests include:

```text
Authorization: Bearer <per-device-agent-token>
X-Device-ID: <device-uuid>
```

## Enrollment

`POST /api/v1/agent/enroll`

The agent submits an enrollment token, hostname, platform, and agent version. The response contains a device UUID and one-time plaintext device token. The server stores only the token digest.

The enrollment token is normally a per-device token created by an administrator (see below). It is accepted once, before its expiry, and only if it has not been revoked; a used, expired, revoked, or unknown token all return `401` with the same message. The optional legacy shared `ENROLLMENT_TOKEN` from `.env` is also accepted when configured, and is reusable.

Administrators manage per-device tokens with their signed-in admin session:

- `POST /api/v1/admin/enrollment-tokens` with `{"label": "optional name", "ttl_minutes": 60}` (1 to 10080 minutes, default 60). The response includes the plaintext `token` exactly once; only its SHA-256 digest is stored.
- `GET /api/v1/admin/enrollment-tokens` lists the 50 most recent tokens with `status` (`active`, `used`, `expired`, or `revoked`) and, for used tokens, the enrolled `device_id`. Plaintext tokens are never returned.
- `DELETE /api/v1/admin/enrollment-tokens/{id}` revokes an unused token (`204`). A token that was already used returns `409`.

## Reporting

`POST /api/v1/agent/report` replaces the latest inventory snapshot. `POST /api/v1/agent/vulnerabilities` replaces the latest normalized vulnerability snapshot. `POST /api/v1/agent/metrics` appends a lightweight resource sample and updates the device's current metrics. `POST /api/v1/agent/heartbeat` updates only the device's last-seen time.

`GET /api/v1/agent/settings` returns the server-managed inventory and monitoring intervals plus GPU/Docker collection toggles. `POST /api/v1/agent/uninstall/verify` validates the optional managed-uninstall code before the provided uninstall helper proceeds.

Installed packages and updates are normalized by the endpoint agent before transmission. This keeps package-manager-specific parsing away from the server.

## Jobs

The agent polls `GET /api/v1/agent/jobs/next`. A `204` response means no work is available. A returned job is atomically moved from `pending` to `running`.

The agent posts the terminal result to `POST /api/v1/agent/jobs/{job_id}/result`. Supported MVP job types are:

- `SCAN_DEVICE`
- `SCAN_VULNERABILITIES`
- `INSTALL_APPROVED_UPDATES` (versioned, approved snapshot)
- `INSTALL_CUSTOM_PACKAGE` (admin-created uploaded bundle)

The previous unrestricted `INSTALL_UPDATES` creation path is disabled. A new approved patch job can only be created from the server's current per-device approvals, either manually or when a patch schedule becomes due. The agent checks currently available versions and Debian's simulated transaction before applying them. Custom bundle jobs can only be queued by an admin from a stored bundle; agents authenticate each file download against their own running job and check the reported digest.

## Administration

Before account setup, legacy administrative routes accept:

```text
X-Admin-Token: <admin-token>
```

After first-admin setup, the legacy header no longer authorizes dashboard/API access. Log in with `POST /api/v1/auth/login`, send the returned `X-CSRF-Token` value on writes alongside the HttpOnly session cookie, and send `X-FleetView-Request: 1` for login, setup, and logout. `GET /api/v1/auth/status` reports whether initial setup is required. Use `POST /api/v1/auth/setup` with the existing admin token to create the first admin. For user creation, role/active changes, password resets, and audit history, see `/api/v1/admin/users` and `/api/v1/admin/users/audit/recent`. Admins can change their own password through `/api/v1/auth/password`.

Viewer accounts can read the fleet; operator accounts can queue scan, patch, and package jobs and edit the catalog/schedules; admin accounts can manage devices, enrollment, fleet settings, and users. For request and response schemas, use `/api/docs` on the server.

The current interface exposes device listing/detail, the most recent 100 jobs, job creation, `PUT /api/v1/admin/devices/{device_id}/settings`, and `GET /api/v1/admin/devices/{device_id}/metrics?hours=24` for one to 168 hours of retained telemetry. It intentionally does not expose a generic remote shell.
## FleetView 0.12.0 additions

The endpoints below require a signed-in account with the applicable role after account setup.

- POST /api/v1/admin/devices/{device_id}/jobs accepts
  `{"type":"UNINSTALL_PACKAGE","options":{"package":"htop","confirmed":true}}`.
  One literal package name/ID is required; shell expressions and options are rejected.
  Existing pending/running jobs of the same type return 409.
  Upgrade the target agent to 0.12.0 before queueing uninstall jobs.
- GET/PUT /api/v1/admin/devices/{device_id}/vulnerability-schedule reads/writes
  `{"interval_hours":24}`. Zero disables; accepted range 0–8760.
  Response includes interval_hours, next_run_at and supported.
  Unsupported platforms cannot enable schedules (400); unknown devices return 404.
  Schedules persist in a new additive table. Saving resets the next due time.
  Agent polling queues overdue work atomically; missed intervals collapse,
  and pending/running scans prevent another scheduled job.
  Disabled schedules leave existing jobs untouched. No root cron or inbound
  endpoint connection is required.
- GET /api/v1/admin/reports/history accepts optional device_id and paired
  start/end ISO dates (inclusive UTC). Without dates, days defaults to 30.
  Ranges up to 3660 days are supported. Invalid/reversed/unpaired ranges fail,
  missing devices return 404, and days with no snapshots are omitted.
  Existing snapshot retention is unchanged; history cannot be backfilled.

## FleetView 0.14.0 additions

- `GET/PUT /api/v1/admin/devices/{device_id}/patch-approvals` lists pending versions with an `approved` flag or sets `{ "package": "curl", "available_version": "2.0", "approved": true }`. An approval is tied to the scanned version, not just the name.
- `POST /api/v1/admin/devices/{device_id}/deploy-approved-patches` queues the current approved version snapshot. The server requires agent version 0.14.0. On Arch, the entire pending set must be approved.
- `GET/PUT /api/v1/admin/devices/{device_id}/patch-schedule` reads/sets `{ "interval_hours": 24 }`; zero disables.
- `GET/POST /api/v1/admin/custom-packages` lists/creates immutable bundles. POST is multipart with `name`, `platform` (`linux` or `windows`), `command`, and 1–5 `files`. Creation is admin-only. Files are at most 8 MiB individually and 16 MiB combined.
- `POST /api/v1/admin/custom-packages/{package_id}/devices/{device_id}/deploy` queues a compatible custom installer job, admin-only.
- `GET /api/v1/agent/jobs/{job_id}/bundle` supplies the manifest for that agent's running job; `GET /api/v1/agent/jobs/{job_id}/bundle/files/{file_id}` supplies one authenticated file. Other devices and completed jobs cannot fetch the bundle.

## FleetView 0.15.0 additions

- `POST /api/v1/admin/devices/{device_id}/jobs` accepts `{ "type": "DOCKER_CONTAINER_ACTION", "options": { "action": "start", "container_id": "abcdef012345", "confirmed": true } }`; `stop` and `restart` are also accepted. Operators and admins can queue an action for a container ID in that device's latest Docker inventory when its native agent reports version 0.15.0 or later. Duplicate pending/running Docker actions for the same device receive HTTP 409. Check `GET /api/v1/admin/jobs` for the result.
