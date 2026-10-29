#!/usr/bin/env bash
# Package the bin-sbom run-time data for hosting, so other machines can install it
# with ./fetch-bin-sbom-data.sh instead of rebuilding it.
#
# Bundled:
#   database/                  preprocessor.py output, ~1.1GB
#   osscollector/repo_meta/    component metadata detector.py needs to name components
#
# Not bundled: osscollector/repo_src, repo_funcCode and friends (~4GB) are inputs to
# the database build, and nothing reads them at scan time. Ghidra is not bundled
# either -- fetch-bin-sbom-data.sh pulls it straight from its public release.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BSG_DIR="$ROOT_DIR/Binary_SBOM_Generator"
OUTPUT="${1:-$ROOT_DIR/bin-sbom-data.tar.gz}"

for required in "$BSG_DIR/database" "$BSG_DIR/osscollector/repo_meta"; do
    if [ ! -d "$required" ]; then
        echo "[-] Error: nothing to package, '$required' does not exist." >&2
        echo "    Build it first: cd Binary_SBOM_Generator && uv run python src/preprocessor.py" >&2
        exit 1
    fi
done

echo "[*] Packaging bin-sbom data into '$OUTPUT'..."
echo "    database/               $(du -sh "$BSG_DIR/database" | cut -f1)"
echo "    osscollector/repo_meta/ $(du -sh "$BSG_DIR/osscollector/repo_meta" | cut -f1)"

# Written to a temporary name first so an interrupted run cannot leave a truncated
# archive sitting at the path someone is about to upload.
tar czf "$OUTPUT.partial" -C "$BSG_DIR" database osscollector/repo_meta
mv "$OUTPUT.partial" "$OUTPUT"

echo "[+] Wrote '$OUTPUT' ($(du -sh "$OUTPUT" | cut -f1))."
echo
echo "Next: host it where your team can download it, then on another machine run"
echo "    BIN_SBOM_DATA_URL=<url> ./fetch-bin-sbom-data.sh"
