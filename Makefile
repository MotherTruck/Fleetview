PROJECT_VERSION ?= 0.22.0

.PHONY: up down logs test package agent

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f server

# Runs the real test suites (server-rs's integration tests need a local
# Postgres reachable as `sudo -u postgres psql`, with a `fleetview` role
# that owns the per-test databases it creates and drops -- see
# server-rs/tests/common/mod.rs -- and the agent's cross-platform build
# checks need no services at all).
test:
	cd server-rs && cargo test -- --test-threads=4
	cd agent && go build ./... && go vet ./... && go test ./...
	cd agent && GOOS=windows go build ./... && GOOS=freebsd go build ./...

agent:
	cd agent && go build -trimpath -ldflags="-s -w" -o bin/fleetview-agent ./cmd/fleetview-agent

package:
	mkdir -p dist
	project_dir="$$(basename "$$(pwd)")"; \
	tar --exclude="$$project_dir/.env" --exclude="$$project_dir/dist" --exclude="$$project_dir/agent/bin" -C .. -czf dist/fleetview-mvp-$(PROJECT_VERSION).tar.gz "$$project_dir"
