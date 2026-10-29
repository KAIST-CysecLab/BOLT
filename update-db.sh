#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
mkdir -p .cache

# The bolt service gets the compose database's DSN from docker-compose.yml.
# BOLT_MYSQL_DSN points the update at another database instead.
dsn_args=()
if [ -n "${BOLT_MYSQL_DSN:-}" ]; then
  dsn_args=(--mysql-dsn "$BOLT_MYSQL_DSN")
fi

# The volume is retained. This runs for both a new and an existing database.
docker compose up -d --wait --wait-timeout 120 mysql
exec docker compose run --rm bolt image \
  --download-db-only \
  --timeout 30m \
  ${dsn_args[@]+"${dsn_args[@]}"} \
  --db-repository ghcr.io/aquasecurity/trivy-db:2 \
  "$@"
