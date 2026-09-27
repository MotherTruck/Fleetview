#!/usr/bin/env bash
# Read-only diagnostic: why can't I reach the FleetView dashboard from another machine?
# Run on the machine that runs Docker, from the project directory:
#   ./scripts/check-access.sh
# Nothing is modified. Secrets from .env are never printed.
set -uo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

# Read a single non-secret key from .env without sourcing the file.
env_value() {
  [[ -f .env ]] || return 0
  grep -E "^$1=" .env | tail -n1 | cut -d= -f2- | tr -d "\"'"
}

bind_address="$(env_value FLEETVIEW_BIND_ADDRESS)"
port="$(env_value FLEETVIEW_PORT)"
bind_address="${bind_address:-127.0.0.1}"
port="${port:-8080}"

section() { printf '\n== %s ==\n' "$1"; }

section "Configuration"
if [[ -f .env ]]; then
  echo ".env found"
else
  echo ".env NOT found (docker compose will refuse to start without it)"
fi
echo "FLEETVIEW_BIND_ADDRESS=$bind_address"
echo "FLEETVIEW_PORT=$port"
case "$bind_address" in
  127.0.0.1|localhost)
    echo "-> Loopback only: the dashboard is reachable from THIS machine only."
    echo "   To reach it from a VM host or another device, set FLEETVIEW_BIND_ADDRESS to this"
    echo "   machine's LAN/VM IP (or 0.0.0.0 on a trusted network) and re-run 'docker compose up -d'."
    ;;
  0.0.0.0)
    echo "-> Published on all interfaces."
    ;;
  *)
    echo "-> Published only on $bind_address. Browse to http://$bind_address:$port"
    ;;
esac

section "Containers"
if command -v docker >/dev/null 2>&1; then
  docker compose ps 2>&1 || sudo docker compose ps 2>&1 || echo "Could not run 'docker compose ps' (try with sudo)."
  echo
  echo "Published port mapping for the server container:"
  docker compose port server 8080 2>&1 || sudo docker compose port server 8080 2>&1 || echo "(not published or not running)"
else
  echo "docker not found on PATH"
fi

section "Listening socket for port $port"
if command -v ss >/dev/null 2>&1; then
  ss -ltn "sport = :$port" 2>&1
else
  echo "ss not available"
fi

section "Health check from this machine"
if command -v curl >/dev/null 2>&1; then
  for host in 127.0.0.1 "$bind_address"; do
    [[ "$host" == "0.0.0.0" ]] && host="127.0.0.1"
    printf '%s:%s/healthz -> ' "$host" "$port"
    curl -s -m 5 -o /dev/null -w '%{http_code}\n' "http://$host:$port/healthz" || echo "failed"
  done | awk '!seen[$0]++'
else
  echo "curl not available"
fi

section "This machine's IPv4 addresses"
if command -v ip >/dev/null 2>&1; then
  ip -4 -o addr show scope global 2>/dev/null | awk '{print $2": "$4}'
else
  hostname -I 2>/dev/null || echo "could not list addresses"
fi

section "Firewall (informational)"
if command -v ufw >/dev/null 2>&1; then
  sudo -n ufw status 2>/dev/null || echo "ufw present; run 'sudo ufw status' to inspect"
fi
if command -v firewall-cmd >/dev/null 2>&1; then
  sudo -n firewall-cmd --state 2>/dev/null || echo "firewalld present; run 'sudo firewall-cmd --list-all' to inspect"
fi
if command -v nft >/dev/null 2>&1; then
  echo "nftables present; inspect with 'sudo nft list ruleset' if connections are still refused."
fi
echo "Note: Docker inserts its own rules for published ports, so host firewall rules such as"
echo "'ufw deny 8080' may not restrict them. Prefer binding to a specific IP over relying on ufw."

cat <<EOF

== Next step ==
From the OTHER machine (e.g. your VM host), test:
  curl -m 5 http://<address-from-above>:$port/healthz
Expected: {"status":"ok"}
EOF
