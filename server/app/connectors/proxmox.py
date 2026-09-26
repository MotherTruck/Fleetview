"""Outbound client for the Proxmox VE REST API.

Auth is an API token (Datacenter -> Permissions -> API Tokens in the
Proxmox UI), sent as the header Proxmox's own docs specify:
`Authorization: PVEAPIToken=<user>@<realm>!<tokenid>=<secret>`. Every
Proxmox API response is wrapped in a top-level "data" key.
"""
import httpx

REQUIRED_CREDENTIAL_FIELDS = ("token_id", "token_secret")


class ProxmoxError(Exception):
    pass


def fetch_inventory(base_url: str, credentials: dict, verify_tls: bool = True, timeout: float = 10.0) -> dict:
    token_id = credentials.get("token_id", "")
    token_secret = credentials.get("token_secret", "")
    headers = {"Authorization": f"PVEAPIToken={token_id}={token_secret}"}
    base = base_url.rstrip("/")

    with httpx.Client(verify=verify_tls, timeout=timeout, headers=headers) as client:
        try:
            nodes_response = client.get(f"{base}/api2/json/nodes")
            nodes_response.raise_for_status()
        except httpx.HTTPStatusError as error:
            status = error.response.status_code
            reason = "check the API token and that it has PVEAuditor (or greater) permission" if status in (401, 403) else f"HTTP {status}"
            raise ProxmoxError(f"Proxmox API returned {status}: {reason}") from error
        except httpx.RequestError as error:
            raise ProxmoxError(f"Could not reach Proxmox at {base}: {error}") from error

        nodes = nodes_response.json().get("data", [])
        if not isinstance(nodes, list):
            raise ProxmoxError("Unexpected response from Proxmox's /nodes endpoint")

        vms: list[dict] = []
        containers: list[dict] = []
        for node in nodes:
            node_name = node.get("node")
            if not node_name:
                continue
            for guest_type, bucket in (("qemu", vms), ("lxc", containers)):
                try:
                    response = client.get(f"{base}/api2/json/nodes/{node_name}/{guest_type}")
                    response.raise_for_status()
                except httpx.HTTPError:
                    # One node being slow/unreachable shouldn't blank the
                    # rest of a healthy cluster's inventory.
                    continue
                for guest in response.json().get("data", []) or []:
                    if isinstance(guest, dict):
                        bucket.append({**guest, "node": node_name})

        return {"nodes": nodes, "vms": vms, "containers": containers}
