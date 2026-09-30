# fleetview-server (Rust)

The management server -- what `server/Dockerfile` and `docker-compose.yml`
actually build and deploy. Originally written as a from-scratch Rust
reimplementation of `server/` (Python/FastAPI) built incrementally
alongside it; that Python implementation is now kept in the repo for
reference only and is no longer built or run.

Axum + tokio + sqlx, Postgres only: production always runs Postgres (see
`../docker-compose.yml`), so this targets it exclusively rather than also
supporting SQLite the way the Python server's test suite does. Tests here
run against a real local Postgres instance instead.

## Running locally

```sh
# once: a local Postgres role + database for development
sudo -u postgres psql -c "CREATE USER fleetview WITH PASSWORD 'fleetview' CREATEDB;"
sudo -u postgres psql -c "CREATE DATABASE fleetview_dev OWNER fleetview;"

DATABASE_URL="postgres://fleetview:fleetview@localhost/fleetview_dev" cargo run
```

Migrations (`migrations/*.sql`) run automatically on startup via
`sqlx::migrate!`. There's no separate migration command to remember.

## Why Postgres-only diverges from the Python server

`server/app/database.py` supports SQLite specifically so its test suite
doesn't need a database service running. That convenience came with a real
cost documented in that project's own code (`server/app/live.py`'s module
docstring): SQLite's in-memory mode hands a different, schema-less database
to every new thread, which broke a naive implementation under test even
though the equivalent code worked fine against Postgres. Testing this port
against a real Postgres instance throughout avoids that class of surprise
entirely, at the cost of needing Postgres available locally to run `cargo
test` (see above).
