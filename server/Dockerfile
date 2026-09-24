# Cross-compiles the agent for the two published platforms so the
# management server can offer remote "Upgrade agent" jobs (see
# server/app/deployment.py's published_agent_manifest) without any
# endpoint needing its own Go toolchain. The version embedded in these
# binaries (and reported by them) comes straight from the agent's own
# source (main.go's `var version`), so there is exactly one place that
# needs bumping for a release, not a separate build-arg to keep in sync.
FROM golang:1.23-bookworm AS agent-build
WORKDIR /src
COPY agent ./agent
RUN set -e; \
    agent_version="$(sed -n 's/^var version = "\(.*\)"$/\1/p' agent/cmd/fleetview-agent/main.go)"; \
    if [ -z "$agent_version" ]; then echo "could not read agent version from main.go" >&2; exit 1; fi; \
    mkdir -p /out/linux-amd64 /out/windows-amd64; \
    cd agent; \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=${agent_version}" \
      -o /out/linux-amd64/fleetview-agent ./cmd/fleetview-agent; \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=${agent_version}" \
      -o /out/windows-amd64/fleetview-agent.exe ./cmd/fleetview-agent; \
    linux_sha="$(sha256sum /out/linux-amd64/fleetview-agent | cut -d' ' -f1)"; \
    windows_sha="$(sha256sum /out/windows-amd64/fleetview-agent.exe | cut -d' ' -f1)"; \
    printf '{"version":"%s","linux_amd64":{"sha256":"%s","path":"/install/agent-linux-amd64"},"windows_amd64":{"sha256":"%s","path":"/install/agent-windows-amd64.exe"}}' \
      "$agent_version" "$linux_sha" "$windows_sha" > /out/manifest.json

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 --create-home fleetview
COPY server/app ./app
COPY agent /opt/fleetview-install/source/agent
COPY scripts/uninstall-agent.sh /opt/fleetview-install/source/scripts/uninstall-agent.sh
COPY scripts/install-agent.ps1 /opt/fleetview-install/source/scripts/install-agent.ps1
COPY scripts/uninstall-agent.ps1 /opt/fleetview-install/source/scripts/uninstall-agent.ps1
COPY scripts/upgrade-agent-in-place.sh /opt/fleetview-install/source/scripts/upgrade-agent-in-place.sh
COPY scripts/upgrade-agent-in-place.ps1 /opt/fleetview-install/source/scripts/upgrade-agent-in-place.ps1
COPY scripts/remote-install-linux.sh /opt/fleetview-install/install-linux.sh
RUN python -c "import tarfile; t=tarfile.open('/opt/fleetview-install/agent-source.tar.gz','w:gz'); t.add('/opt/fleetview-install/source/agent',arcname='agent'); t.add('/opt/fleetview-install/source/scripts',arcname='scripts'); t.close()" \
    && chmod 0644 /opt/fleetview-install/agent-source.tar.gz /opt/fleetview-install/install-linux.sh
COPY --from=agent-build /out /opt/fleetview-install/agent-bin
RUN chmod 0755 /opt/fleetview-install/agent-bin/linux-amd64/fleetview-agent /opt/fleetview-install/agent-bin/windows-amd64/fleetview-agent.exe \
    && chmod 0644 /opt/fleetview-install/agent-bin/manifest.json
USER fleetview
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]
