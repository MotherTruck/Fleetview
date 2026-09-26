"""Outbound client for the OPNsense REST API.

Auth is HTTP Basic with an API key/secret pair (System -> Access -> Users,
generate an API key for the account), not a session cookie/CSRF-token pair
like the OPNsense web UI itself uses.

OPNsense's DHCP lease endpoint has genuinely varied across versions and
DHCP backends (ISC dhcpd vs. the newer Kea plugin) in ways this project
cannot verify against a real instance in this environment -- this client
requests the endpoint documented for the Kea backend (the current default
on supported OPNsense releases) and fails with a clear, specific error if
the response shape doesn't match what's expected, rather than silently
showing wrong or empty data. See docs/INTEGRATIONS.md.
"""
import httpx


class OPNsenseError(Exception):
    pass


REQUIRED_CREDENTIAL_FIELDS = ("api_key", "api_secret")


def _client(base_url: str, credentials: dict, verify_tls: bool, timeout: float) -> httpx.Client:
    return httpx.Client(
        base_url=base_url.rstrip("/"),
        auth=(credentials.get("api_key", ""), credentials.get("api_secret", "")),
        verify=verify_tls,
        timeout=timeout,
    )


def _get(client: httpx.Client, path: str) -> dict:
    try:
        response = client.get(path)
        response.raise_for_status()
    except httpx.HTTPStatusError as error:
        status = error.response.status_code
        reason = "check the API key/secret" if status in (401, 403) else f"HTTP {status}"
        raise OPNsenseError(f"OPNsense API returned {status} for {path}: {reason}") from error
    except httpx.RequestError as error:
        raise OPNsenseError(f"Could not reach OPNsense: {error}") from error
    try:
        return response.json()
    except ValueError as error:
        raise OPNsenseError(f"OPNsense returned a non-JSON response for {path}") from error


def test_connection(base_url: str, credentials: dict, verify_tls: bool = True, timeout: float = 10.0) -> None:
    """Raises OPNsenseError on failure; used by the "test connection" flow
    before an integration is saved. /core/system/status is a lightweight,
    long-stable endpoint that doesn't depend on which DHCP backend is
    configured, so it's a good way to validate credentials/reachability
    independent of the DHCP-lease-shape uncertainty described above."""
    with _client(base_url, credentials, verify_tls, timeout) as client:
        payload = _get(client, "/api/core/system/status")
    if not isinstance(payload, dict):
        raise OPNsenseError("Unexpected response from OPNsense's system status endpoint")


def fetch_dhcp_leases(base_url: str, credentials: dict, verify_tls: bool = True, timeout: float = 10.0) -> list[dict]:
    with _client(base_url, credentials, verify_tls, timeout) as client:
        payload = _get(client, "/api/dhcpv4/leases/searchLease")
    rows = payload.get("rows") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise OPNsenseError(
            "OPNsense's DHCP lease response didn't have the expected shape (no 'rows' list). "
            "This endpoint varies between OPNsense versions/DHCP backends -- "
            "see docs/INTEGRATIONS.md."
        )
    leases = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        leases.append({
            "ip": row.get("address") or row.get("ip"),
            "mac": row.get("hwaddr") or row.get("mac"),
            "hostname": row.get("hostname") or "",
            "state": row.get("state") or "",
        })
    return leases


def fetch_inventory(base_url: str, credentials: dict, verify_tls: bool = True, timeout: float = 10.0) -> dict:
    return {"dhcp_leases": fetch_dhcp_leases(base_url, credentials, verify_tls, timeout)}
