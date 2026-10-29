#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
echo "fetch-db-dump.sh is deprecated; updating MySQL from the official Trivy DB. Use ./update-db.sh instead." >&2
exec "$SCRIPT_DIR/update-db.sh" "$@"
