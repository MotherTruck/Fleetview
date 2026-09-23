# FleetView 0.12.0

Based on the supplied claude-epc-replacement-continue-v8o0cx archive (0.11.0).
The GitHub repository name is unchanged. This is a source delivery, not a
deployment or pushed PR.

## Features

1. Deploy → catalog → Uninstall: select target devices, then confirm the
   platform-resolved names. Unsupported platforms are skipped and per-device
   queue failures are reported. Job history distinguishes install/removal.
   Upgrade native agents before use.
2. Agent → select a device → automatic vulnerability scan interval:
   enter hours (for example 24 or 168), then Save scan schedule. Zero disables.
   Persisted due times survive server restarts; offline devices catch up on
   their next poll without accumulating missed scans. An active scan prevents
   duplicate scheduled work. Only Arch/CachyOS and Debian are supported.
3. Reports → Trends: select the fleet or one device, start/end UTC dates,
   then Apply date range. Up to ten years of existing snapshots can be queried.
   Missing reporting days are omitted, not counted as clean or offline.
   The cards above Trends continue to show current fleet-wide status.

## Rollout

Preserve .env and back up the database before replacing source. Rebuild the
server using docker compose up -d --build. Use the existing native-agent
upgrade process to deploy 0.12.0. The new schedule table is created on startup;
no existing database columns are removed or changed. Refresh the browser.
First test uninstall on one disposable package/device. APT can remove
dependent packages; no purge or autoremove is requested. Windows removal uses
an exact winget ID and still depends on winget availability to the service.

## Validation

- 37 Python server tests passed, including API authentication, validation,
  schedule due-time handling, duplicate suppression, and report filters.
- Go tests passed for all packages.
- Linux amd64 build and Windows amd64 cross-build passed.
- JavaScript syntax check passed.
- DOM smoke test passed: report filters, schedule saving, uninstall cancellation
  and confirmation (jsdom; not a substitute for visual browser testing).
- Browser visual testing could not run because the Chromium download failed.
- No package was actually removed from an endpoint. Real package-manager
  execution and PostgreSQL multi-worker concurrency need staging validation.

Run server checks with requirements.txt plus httpx installed:
python -m unittest discover -s server/tests -v

Run agent checks from agent/: go test ./...
For source ZIP builds without Git metadata, use go build -buildvcs=false.
