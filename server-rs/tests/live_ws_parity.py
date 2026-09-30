#!/usr/bin/env python3
"""Black-box port of server/tests/test_live.py against the real compiled
Rust server + real Postgres. A standalone script rather than a `cargo test`
file because the WebSocket testing ergonomics (synchronous, multi-socket,
interleaved send/receive) are much better served by Python's `websockets`
library than by adding an async WS client crate to the Rust test harness --
this mirrors the same approach already used (and proven, with zero bugs
found) to verify the live hub during its initial implementation.

Usage: python3 live_ws_parity.py (run from anywhere; paths are relative to
this file). Requires: a local `fleetview`-owned Postgres reachable at
localhost, `sudo -u postgres psql`, `requests`, `websockets` (sync client).
"""
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid

import requests
from websockets.sync.client import connect
from websockets.exceptions import ConnectionClosed

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "target", "debug", "fleetview-server")
ORIGIN = "http://127.0.0.1:9"  # any http origin whose host != the server's bind host, but see below
FAILURES = []


def check(label, condition):
    status = "ok" if condition else "FAIL"
    print(f"[{status}] {label}")
    if not condition:
        FAILURES.append(label)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def run_psql(sql, db="postgres"):
    subprocess.run(
        ["sudo", "-u", "postgres", "psql", "-q", "-d", db, "-v", "ON_ERROR_STOP=1", "-c", sql],
        check=True, stdout=subprocess.DEVNULL,
    )


def main():
    db_name = f"fleetview_test_{uuid.uuid4().hex}"
    run_psql(f"CREATE DATABASE {db_name} OWNER fleetview;")
    database_url = f"postgres://fleetview:fleetview@localhost/{db_name}"
    proc = None
    try:
        env = dict(os.environ)
        env.update({
            "DATABASE_URL": database_url,
            "BIND_ADDR": "127.0.0.1:0",
            "ADMIN_TOKEN": "test-admin-token",
            "FLEETVIEW_SECRET_KEY": "yu30SfPizM0xv2LEurXELmKigTYar_BTRm1vgp8ricc=",
        })
        proc = subprocess.Popen([BIN], env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        port = None
        for line in proc.stdout:
            if line.strip().startswith("listening on "):
                port = line.strip().split(":")[-1]
                break
        if port is None:
            raise RuntimeError("server never printed its listening address")

        base_url = f"http://127.0.0.1:{port}"
        for _ in range(200):
            try:
                if requests.get(f"{base_url}/healthz", timeout=1).ok:
                    break
            except requests.RequestException:
                pass
            time.sleep(0.025)
        else:
            raise RuntimeError("server did not become healthy")

        run_scenarios(base_url, port, db_name)
    finally:
        if proc is not None:
            proc.kill()
            proc.wait()
        subprocess.run(
            ["sudo", "-u", "postgres", "psql", "-q", "-c", f"DROP DATABASE IF EXISTS {db_name} WITH (FORCE);"],
            stdout=subprocess.DEVNULL,
        )

    if FAILURES:
        print(f"\n{len(FAILURES)} FAILURE(S):")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("\nAll live-WS parity checks passed.")


def seed_devices(database_url):
    devices = [
        ("live-new", "fresh", "0.18.0", token_hash("live-secret")),
        ("live-old", "stale", "0.16.0", token_hash("old-secret")),
        ("live-newer", "newer", "0.23.0", token_hash("newer-secret")),
    ]
    for device_id, hostname, agent_version, hashed in devices:
        run_psql(
            f"INSERT INTO devices (id, hostname, platform, package_manager, agent_version, agent_token_hash) "
            f"VALUES ('{device_id}', '{hostname}', 'linux', 'apt', '{agent_version}', '{hashed}');",
            db=database_url.rsplit('/', 1)[-1],
        )


def run_scenarios(base_url, port, db_name):
    seed_devices(f"postgres://fleetview:fleetview@localhost/{db_name}")
    ws_base = f"ws://127.0.0.1:{port}"
    fv_header = {"X-FleetView-Request": "1"}
    origin_header = {"Origin": f"http://127.0.0.1:{port}"}

    admin = requests.Session()
    setup = admin.post(f"{base_url}/api/v1/auth/setup", json={
        "admin_token": "test-admin-token", "username": "admin", "password": "a-long-test-password-123",
    }, headers=fv_header)
    check("admin setup succeeds", setup.status_code == 201)
    admin_csrf = setup.json()["csrf_token"]

    created_viewer = admin.post(f"{base_url}/api/v1/admin/users", json={
        "username": "vwr", "password": "a-long-test-password-123", "role": "viewer",
    }, headers={**fv_header, "X-CSRF-Token": admin_csrf})
    check("viewer user created", created_viewer.status_code == 201)

    admin_cookie = admin.cookies.get("fleetview_session")

    def ws_headers(cookie=None, extra=None):
        headers = dict(origin_header)
        if cookie:
            headers["Cookie"] = f"fleetview_session={cookie}"
        if extra:
            headers.update(extra)
        return headers

    # -- agent socket rejects bad credentials --
    with connect(f"{ws_base}/api/v1/agent/live", additional_headers={"Authorization": "Bearer wrong", "X-Device-Id": "live-new"}) as ws:
        message = json.loads(ws.recv())
        check("agent socket rejects bad credentials (type=error)", message["type"] == "error")
        check("agent socket rejects bad credentials (code=4401)", message["code"] == 4401)

    # -- browser socket requires cookie and trusted origin --
    with connect(f"{ws_base}/api/v1/admin/live-status", additional_headers=ws_headers()) as ws:
        message = json.loads(ws.recv())
        check("no-cookie browser socket rejected 4401", message["code"] == 4401)

    with connect(f"{ws_base}/api/v1/admin/live-status", additional_headers=ws_headers(admin_cookie, {"Origin": "http://evil.example"})) as ws:
        message = json.loads(ws.recv())
        check("untrusted-origin browser socket rejected 4403", message["code"] == 4403)

    # -- must_change_password blocks status/metrics sockets --
    viewer = requests.Session()
    login = viewer.post(f"{base_url}/api/v1/auth/login", json={"username": "vwr", "password": "a-long-test-password-123"}, headers=fv_header)
    check("viewer login succeeds", login.status_code == 200)
    viewer_cookie = viewer.cookies.get("fleetview_session")

    with connect(f"{ws_base}/api/v1/admin/live-status", additional_headers=ws_headers(viewer_cookie)) as ws:
        check("must-change-password blocks live-status (4403)", json.loads(ws.recv())["code"] == 4403)
    with connect(f"{ws_base}/api/v1/admin/devices/live-new/metrics-live", additional_headers=ws_headers(viewer_cookie)) as ws:
        check("must-change-password blocks metrics-live (4403)", json.loads(ws.recv())["code"] == 4403)

    # -- metrics relay and live-status broadcast --
    with connect(f"{ws_base}/api/v1/admin/live-status", additional_headers=ws_headers(admin_cookie)) as status_ws:
        snapshot = json.loads(status_ws.recv())
        check("live-status initial snapshot is empty", snapshot == {"type": "snapshot", "live_device_ids": []})

        with connect(f"{ws_base}/api/v1/agent/live", additional_headers={"Authorization": "Bearer live-secret", "X-Device-Id": "live-new"}) as agent_ws:
            status_event = json.loads(status_ws.recv())
            check("live-status broadcasts agent online", status_event == {"type": "status", "device_id": "live-new", "live": True})

            with connect(f"{ws_base}/api/v1/admin/devices/live-new/metrics-live", additional_headers=ws_headers(admin_cookie)) as metrics_ws:
                initial = json.loads(metrics_ws.recv())
                check("metrics-live initial status is live=True", initial == {"type": "status", "device_id": "live-new", "live": True})

                sample = {
                    "type": "metrics", "recorded_at": "2026-01-01T00:00:00Z", "cpu_percent": 42.5,
                    "memory_used_bytes": 1, "memory_total_bytes": 2, "swap_used_bytes": 0, "swap_total_bytes": 0,
                    "disk_used_bytes": 0, "disk_total_bytes": 0, "load_1": 0, "load_5": 0, "load_15": 0,
                    "network_receive_bps": 0, "network_transmit_bps": 0, "network_receive_bytes": 0,
                    "network_transmit_bytes": 0, "process_count": 1, "uptime_seconds": 1,
                    "top_consumers": [
                        {"kind": "process", "pid": 123, "name": "stress", "cpu_percent": 97.5, "memory_bytes": 1048576},
                        {"kind": "container", "name": "fv-stress-test", "cpu_percent": 100.4, "memory_bytes": 1052672},
                    ],
                }
                agent_ws.send(json.dumps(sample))
                relayed = json.loads(metrics_ws.recv())
                check("relayed metrics type", relayed["type"] == "metrics")
                check("relayed metrics device_id", relayed["device_id"] == "live-new")
                check("relayed metrics cpu_percent", relayed["cpu_percent"] == 42.5)
                check("relayed top_consumers[0].name", relayed["top_consumers"][0]["name"] == "stress")
                check("relayed top_consumers[1].kind", relayed["top_consumers"][1]["kind"] == "container")

        offline_event = json.loads(status_ws.recv())
        check("live-status broadcasts agent offline", offline_event == {"type": "status", "device_id": "live-new", "live": False})

    # -- terminal: role/version gates + single-session enforcement --
    with connect(f"{ws_base}/api/v1/admin/devices/live-new/terminal-live", additional_headers=ws_headers(viewer_cookie)) as ws:
        check("viewer blocked from terminal-live (4403)", json.loads(ws.recv())["code"] == 4403)
    with connect(f"{ws_base}/api/v1/admin/devices/live-old/terminal-live", additional_headers=ws_headers(admin_cookie)) as ws:
        check("old agent blocked from terminal-live (4409)", json.loads(ws.recv())["code"] == 4409)
    with connect(f"{ws_base}/api/v1/admin/devices/live-new/terminal-live", additional_headers=ws_headers(admin_cookie)) as ws:
        check("disconnected agent blocked from terminal-live (4410)", json.loads(ws.recv())["code"] == 4410)

    with connect(f"{ws_base}/api/v1/agent/live", additional_headers={"Authorization": "Bearer live-secret", "X-Device-Id": "live-new"}) as agent_ws:
        with connect(f"{ws_base}/api/v1/admin/devices/live-new/terminal-live", additional_headers=ws_headers(admin_cookie)) as term_ws:
            start = json.loads(agent_ws.recv())
            check("terminal_start relayed to agent", start["type"] == "terminal_start")
            session_id = start["session"]

            with connect(f"{ws_base}/api/v1/admin/devices/live-new/terminal-live", additional_headers=ws_headers(admin_cookie)) as second:
                check("second concurrent terminal refused (4429)", json.loads(second.recv())["code"] == 4429)

            term_ws.send(json.dumps({"type": "input", "data": "ZWNobyBoaQ=="}))
            relayed_input = json.loads(agent_ws.recv())
            check("terminal input relayed", relayed_input == {"type": "terminal_input", "session": session_id, "data": "ZWNobyBoaQ=="})

            term_ws.send(json.dumps({"type": "resize", "cols": 120, "rows": 40}))
            relayed_resize = json.loads(agent_ws.recv())
            check("terminal resize relayed", relayed_resize == {"type": "terminal_resize", "session": session_id, "cols": 120, "rows": 40})

            agent_ws.send(json.dumps({"type": "terminal_output", "session": session_id, "data": "aGk="}))
            check("terminal output relayed to browser", json.loads(term_ws.recv()) == {"type": "terminal_output", "session": session_id, "data": "aGk="})

        stop = json.loads(agent_ws.recv())
        check("terminal_stop sent to agent on browser disconnect", stop == {"type": "terminal_stop", "session": session_id})

    # -- screen (remote control): role/version gates + relay --
    with connect(f"{ws_base}/api/v1/admin/devices/live-newer/screen-live", additional_headers=ws_headers(viewer_cookie)) as ws:
        check("viewer blocked from screen-live (4403)", json.loads(ws.recv())["code"] == 4403)
    with connect(f"{ws_base}/api/v1/admin/devices/live-new/screen-live", additional_headers=ws_headers(admin_cookie)) as ws:
        check("agent too old for remote control (4409)", json.loads(ws.recv())["code"] == 4409)
    with connect(f"{ws_base}/api/v1/admin/devices/live-newer/screen-live", additional_headers=ws_headers(admin_cookie)) as ws:
        check("disconnected agent blocked from screen-live (4410)", json.loads(ws.recv())["code"] == 4410)

    with connect(f"{ws_base}/api/v1/agent/live", additional_headers={"Authorization": "Bearer newer-secret", "X-Device-Id": "live-newer"}) as agent_ws:
        with connect(f"{ws_base}/api/v1/admin/devices/live-newer/screen-live", additional_headers=ws_headers(admin_cookie)) as screen_ws:
            start = json.loads(agent_ws.recv())
            check("screen_start relayed to agent", start["type"] == "screen_start")
            session_id = start["session"]

            with connect(f"{ws_base}/api/v1/admin/devices/live-newer/screen-live", additional_headers=ws_headers(admin_cookie)) as second:
                check("second concurrent remote-control refused (4429)", json.loads(second.recv())["code"] == 4429)

            agent_ws.send(json.dumps({"type": "screen_info", "session": session_id, "width": 1280, "height": 800}))
            check("screen_info relayed to browser", json.loads(screen_ws.recv()) == {"type": "screen_info", "session": session_id, "width": 1280, "height": 800})

            agent_ws.send(b"\xff\xd8fake-jpeg-bytes")
            check("binary frame relayed to browser", screen_ws.recv() == b"\xff\xd8fake-jpeg-bytes")

            screen_ws.send(json.dumps({"type": "mouse_move", "x": 0.5, "y": 0.25}))
            check("mouse_move relayed to agent", json.loads(agent_ws.recv()) == {"type": "mouse_move", "session": session_id, "x": 0.5, "y": 0.25})

            screen_ws.send(json.dumps({"type": "mouse_button", "x": 0.5, "y": 0.25, "button": "left", "pressed": True}))
            check("mouse_button relayed to agent", json.loads(agent_ws.recv()) == {
                "type": "mouse_button", "session": session_id, "x": 0.5, "y": 0.25, "button": "left", "pressed": True,
            })

            # Out-of-range coordinates must be dropped, not relayed -- prove
            # it by sending a subsequent, distinguishable message and
            # checking that's what arrives next (not the dropped one).
            screen_ws.send(json.dumps({"type": "mouse_move", "x": 1.5, "y": 0.25}))
            screen_ws.send(json.dumps({"type": "mouse_scroll", "dx": 0, "dy": -3}))
            check("out-of-range mouse_move dropped, next relayed message is mouse_scroll",
                  json.loads(agent_ws.recv()) == {"type": "mouse_scroll", "session": session_id, "dx": 0, "dy": -3})

            screen_ws.send(json.dumps({"type": "key", "key": "Enter", "pressed": True}))
            check("key event relayed to agent", json.loads(agent_ws.recv()) == {"type": "key", "session": session_id, "key": "Enter", "pressed": True})

        stop = json.loads(agent_ws.recv())
        check("screen_stop sent to agent on browser disconnect", stop == {"type": "screen_stop", "session": session_id})


if __name__ == "__main__":
    main()
