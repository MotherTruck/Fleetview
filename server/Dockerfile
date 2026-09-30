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
     scripts/upgrade-agent-in-place.sh scripts/upgrade-agent-in-place.ps1 ./scripts/
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
      "$agent_version" "$linux_sha" "$windows_sha" > /out/manifest.json; \
    cd /src; \
    tar czf /out/agent-source.tar.gz agent scripts; \
    sha256sum /out/agent-source.tar.gz | cut -d' ' -f1 > /out/agent-source.sha256

FROM rust:1.83-bookworm AS server-build
WORKDIR /src
COPY server-rs ./server-rs
RUN cd server-rs && cargo build --release --locked

FROM debian:bookworm-slim

# No `apt-get install` here on purpose: reqwest/sqlx use rustls with the
# bundled webpki-roots CA store (see Cargo.lock), never the OS's
# /etc/ssl/certs, so this image needs no ca-certificates package; useradd
# is already part of this base image. HEALTHCHECK below uses bash's builtin
# /dev/tcp instead of curl/wget for the same reason -- one less thing to
# install, and one less thing that can go stale.
RUN useradd --system --uid 10001 --create-home fleetview

WORKDIR /app
COPY --from=server-build /src/server-rs/target/release/fleetview-server ./fleetview-server
COPY server/app/static ./static
COPY scripts/remote-install-linux.sh /opt/fleetview-install/install-linux.sh
COPY --from=agent-build /out/agent-source.tar.gz /out/agent-source.sha256 /opt/fleetview-install/
COPY --from=agent-build /out/linux-amd64 /opt/fleetview-install/agent-bin/linux-amd64
COPY --from=agent-build /out/windows-amd64 /opt/fleetview-install/agent-bin/windows-amd64
COPY --from=agent-build /out/manifest.json /opt/fleetview-install/agent-bin/manifest.json
RUN chmod 0644 /opt/fleetview-install/agent-source.tar.gz /opt/fleetview-install/agent-source.sha256 \
      /opt/fleetview-install/install-linux.sh /opt/fleetview-install/agent-bin/manifest.json \
    && chmod 0755 /opt/fleetview-install/agent-bin/linux-amd64/fleetview-agent \
      /opt/fleetview-install/agent-bin/windows-amd64/fleetview-agent.exe \
    && chown -R fleetview:fleetview /app

USER fleetview
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --retries=10 \
    CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/8080 && printf "GET /healthz HTTP/1.0\r\n\r\n" >&3 && head -1 <&3 | grep -q " 200 "' || exit 1
CMD ["./fleetview-server"]
