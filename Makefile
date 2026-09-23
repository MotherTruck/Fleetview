PROJECT_VERSION ?= 0.15.1

.PHONY: up down logs test package agent

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f server

test:
	python3 -m unittest discover -s server/tests -v

agent:
	cd agent && go build -trimpath -ldflags="-s -w" -o bin/fleetview-agent ./cmd/fleetview-agent

package:
	mkdir -p dist
	project_dir="$$(basename "$$(pwd)")"; \
	tar --exclude="$$project_dir/.env" --exclude="$$project_dir/dist" --exclude="$$project_dir/agent/bin" --exclude='__pycache__' --exclude='*.pyc' -C .. -czf dist/fleetview-mvp-$(PROJECT_VERSION).tar.gz "$$project_dir"
