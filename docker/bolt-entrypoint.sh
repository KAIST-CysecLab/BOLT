#!/usr/bin/env bash
set -euo pipefail

# Compatibility for callers that used the old SQL bootstrap. Initialization now
# uses the same official database updater as update-db.sh; BOLT_DB_SQL is ignored.
# The target database must exist and MySQL must be ready before this starts.

if [[ "${BOLT_INIT_DB:-0}" == "1" ]]; then
  bolt_init_dsn="${BOLT_MYSQL_DSN:-${TRIVY_MYSQL_DSN:-}}"
  if [[ -z "$bolt_init_dsn" ]]; then
    : "${MYSQL_HOST:?MYSQL_HOST or BOLT_MYSQL_DSN is required when BOLT_INIT_DB=1}"
    : "${MYSQL_PORT:=3306}"
    : "${MYSQL_USER:?MYSQL_USER is required when BOLT_INIT_DB=1}"
    : "${MYSQL_PASSWORD:?MYSQL_PASSWORD is required when BOLT_INIT_DB=1}"
    : "${MYSQL_DATABASE:?MYSQL_DATABASE is required when BOLT_INIT_DB=1}"
    bolt_init_dsn="${MYSQL_USER}:${MYSQL_PASSWORD}@tcp(${MYSQL_HOST}:${MYSQL_PORT})/${MYSQL_DATABASE}"
  fi
  echo "BOLT_INIT_DB=1: updating MySQL from the official Trivy DB; SQL dumps are no longer imported." >&2
  /usr/local/bin/bolt image --download-db-only --timeout 30m \
    --mysql-dsn "$bolt_init_dsn" \
    --db-repository ghcr.io/aquasecurity/trivy-db:2
fi

exec /usr/local/bin/bolt "$@"
