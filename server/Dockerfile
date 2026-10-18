# Cross-compiles the agent for the two published platforms so the
# management server can offer remote "Upgrade agent" jobs (see
# server-rs/src/deployment.rs's published_agent_manifest) without any
# endpoint needing its own Go toolchain. The version embedded in these
# binaries (and reported by them) comes straight from the agent's own
# source (main.go's `var version`), so there is exactly one place that
# needs bumping for a release, not a separate build-arg to keep in sync.
# Also assembles the downloadable agent-source tarball here (this stage
# already has `tar`, `go`, and the full source tree; nothing else in the
# final image needs to).
FROM golang:1.23-bookworm AS agent-build
WORKDIR /src
COPY agent ./agent
COPY scripts/uninstall-agent.sh scripts/install-agent.ps1 scripts/uninstall-agent.ps1 \
     scripts/upgrade-agent-in-place.sh scripts/upgrade-agent-in-place.ps1 \
     scripts/uninstall-agent-opnsense.sh ./scripts/
COPY agent/packaging/fleetview-agent.rc ./scripts/fleetview-agent.rc
RUN set -e; \
    agent_version="$(sed -n 's/^var version = "\(.*\)"$/\1/p' agent/cmd/fleetview-agent/main.go)"; \
    if [ -z "$agent_version" ]; then echo "could not read agent version from main.go" >&2; exit 1; fi; \
    mkdir -p /out/linux-amd64 /out/windows-amd64 /out/freebsd-amd64; \
    cd agent; \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=${agent_version}" \
      -o /out/linux-amd64/fleetview-agent ./cmd/fleetview-agent; \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=${agent_version}" \
      -o /out/windows-amd64/fleetview-agent.exe ./cmd/fleetview-agent; \
    CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=${agent_version}" \
      -o /out/freebsd-amd64/fleetview-agent ./cmd/fleetview-agent; \
    linux_sha="$(sha256sum /out/linux-amd64/fleetview-agent | cut -d' ' -f1)"; \
    windows_sha="$(sha256sum /out/windows-amd64/fleetview-agent.exe | cut -d' ' -f1)"; \
    freebsd_sha="$(sha256sum /out/freebsd-amd64/fleetview-agent | cut -d' ' -f1)"; \
    printf '{"version":"%s","linux_amd64":{"sha256":"%s","path":"/install/agent-linux-amd64"},"windows_amd64":{"sha256":"%s","path":"/install/agent-windows-amd64.exe"},"freebsd_amd64":{"sha256":"%s","path":"/install/agent-freebsd-amd64"}}' \
      "$agent_version" "$linux_sha" "$windows_sha" "$freebsd_sha" > /out/manifest.json; \
    cd /src; \
    tar czf /out/agent-source.tar.gz agent scripts; \
    sha256sum /out/agent-source.tar.gz | cut -d' ' -f1 > /out/agent-source.sha256

# Pinned to the exact toolchain this Cargo.lock has actually been built
# and tested with throughout development (rustc --version). A number of
# transitive dependencies (e.g. time-core) require Cargo's edition2024
# feature, stabilized in 1.85 -- the previous 1.83 pin failed to parse
# those manifests at all, which is why every CI image build since the
# Rust cutover silently failed and ghcr.io kept serving the last
# successfully-published (pre-Rust) image.
FROM rust:1.94-bookworm AS server-build
WORKDIR /src
COPY server-rs ./server-rs
RUN cd server-rs && cargo build --release --locked

FROM debian:bookworm-slim

# postgresql-client is needed for the admin "Server migration" feature
# (server-rs/src/migration.rs shells out to pg_dump/pg_restore to move the
# whole database to a freshly-provisioned target server) -- the one thing
# in this image that still needs apt-get, now that reqwest/sqlx's rustls
# (bundled webpki-roots, see Cargo.lock) no longer needs ca-certificates
# either. useradd is already part of this base image. HEALTHCHECK below
# uses bash's builtin /dev/tcp instead of curl/wget -- one less thing to
# install, and one less thing that can go stale.
RUN apt-get update \
    && apt-get install -y --no-install-recommends postgresql-client \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home fleetview

WORKDIR /app
COPY --from=server-build /src/server-rs/target/release/fleetview-server ./fleetview-server
COPY server/app/static ./static
COPY scripts/remote-install-linux.sh /opt/fleetview-install/install-linux.sh
COPY scripts/install-agent.ps1 /opt/fleetview-install/windows.ps1
COPY scripts/install-agent-opnsense.sh /opt/fleetview-install/opnsense.sh
COPY scripts/uninstall-agent-opnsense.sh /opt/fleetview-install/uninstall-agent-opnsense.sh
COPY agent/packaging/fleetview-agent.rc /opt/fleetview-install/agent-freebsd.rc
COPY --from=agent-build /out/agent-source.tar.gz /out/agent-source.sha256 /opt/fleetview-install/
COPY --from=agent-build /out/linux-amd64 /opt/fleetview-install/agent-bin/linux-amd64
COPY --from=agent-build /out/windows-amd64 /opt/fleetview-install/agent-bin/windows-amd64
COPY --from=agent-build /out/freebsd-amd64 /opt/fleetview-install/agent-bin/freebsd-amd64
COPY --from=agent-build /out/manifest.json /opt/fleetview-install/agent-bin/manifest.json
RUN chmod 0644 /opt/fleetview-install/agent-source.tar.gz /opt/fleetview-install/agent-source.sha256 \
      /opt/fleetview-install/install-linux.sh /opt/fleetview-install/windows.ps1 \
      /opt/fleetview-install/opnsense.sh /opt/fleetview-install/uninstall-agent-opnsense.sh \
      /opt/fleetview-install/agent-freebsd.rc /opt/fleetview-install/agent-bin/manifest.json \
    && chmod 0755 /opt/fleetview-install/agent-bin/linux-amd64/fleetview-agent \
      /opt/fleetview-install/agent-bin/windows-amd64/fleetview-agent.exe \
      /opt/fleetview-install/agent-bin/freebsd-amd64/fleetview-agent \
    && chown -R fleetview:fleetview /app

USER fleetview
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --retries=10 \
    CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/8080 && printf "GET /healthz HTTP/1.0\r\n\r\n" >&3 && head -1 <&3 | grep -q " 200 "' || exit 1
CMD ["./fleetview-server"]
