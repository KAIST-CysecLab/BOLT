#!/usr/bin/env bash
# Provision the bin-sbom run-time data that this repository does not carry.
#
# `--binary-sbom bin-sbom` needs three things .gitignore keeps out of git because of
# their size:
#
#   Binary_SBOM_Generator/database/                          component DB, ~1.1GB
#   Binary_SBOM_Generator/osscollector/repo_meta/            component metadata
#   Binary_SBOM_Generator/tools/ghidra/ghidra_11.2.1_PUBLIC  Ghidra install, ~640MB
#
# docker-compose.yml mounts this checkout at /work and points BIN_SBOM_DB and
# BIN_SBOM_GHIDRA at those paths.
#
# Ghidra is fetched from its public release. No component database is distributed or
# downloaded: build one from the OSS sources you choose (see "Build the component
# database" in README.md). This script only reports whether one is present.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BSG_DIR="$ROOT_DIR/Binary_SBOM_Generator"

GHIDRA_VERSION="11.2.1"
GHIDRA_DIRNAME="ghidra_${GHIDRA_VERSION}_PUBLIC"
GHIDRA_ZIP="ghidra_${GHIDRA_VERSION}_PUBLIC_20241105.zip"
GHIDRA_DEFAULT_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_ZIP}"
GHIDRA_URL="${BIN_SBOM_GHIDRA_URL:-$GHIDRA_DEFAULT_URL}"
# SHA-256 published in the Ghidra 11.2.1 release notes. It is checked only for the
# default URL: a mirror given with BIN_SBOM_GHIDRA_URL is the caller's to vouch for.
GHIDRA_SHA256="ce4db5117da0fbaf8f33863fec4f40902f754f06b68945a59fb1c0f9b1bc461c"

# Staging directories are registered here rather than cleaned by a RETURN trap: a
# trap set inside a function stays installed afterwards and would fire again on every
# later function return.
STAGING_DIRS=()

cleanup_staging() {
    [ "${#STAGING_DIRS[@]}" -gt 0 ] || return 0
    rm -rf "${STAGING_DIRS[@]}"
}

trap cleanup_staging EXIT

require_cmd() {
    local cmd
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || {
            echo "[-] Error: '$cmd' is required by $(basename "$0") but was not found." >&2
            exit 1
        }
    done
}

# Treat the database as present only when every part preprocessor.py emits is there:
# a run interrupted mid-extract would otherwise be mistaken for a finished install and
# fail much later, inside the scan.
component_db_present() {
    [ -f "$BSG_DIR/database/cb_blocks.index" ] &&
    [ -f "$BSG_DIR/database/cb_blocks_meta.json" ] &&
    [ -d "$BSG_DIR/database/componentDB" ] &&
    [ -d "$BSG_DIR/database/functionFeatures" ] &&
    compgen -G "$BSG_DIR/osscollector/repo_meta/*.txt" > /dev/null
}

ghidra_present() {
    [ -x "$BSG_DIR/tools/ghidra/$GHIDRA_DIRNAME/support/analyzeHeadless" ]
}

fetch_ghidra() {
    if ghidra_present; then
        echo "[*] Ghidra $GHIDRA_VERSION already installed."
        return
    fi

    local verify=false
    if [ "$GHIDRA_URL" = "$GHIDRA_DEFAULT_URL" ]; then
        verify=true
    fi

    require_cmd wget unzip
    if [ "$verify" = true ]; then
        require_cmd sha256sum
    fi

    echo "[*] Downloading Ghidra $GHIDRA_VERSION (~640MB)..."
    local tmp_dir
    tmp_dir="$(mktemp -d "$BSG_DIR/tools/.ghidra-download.XXXXXX")"
    STAGING_DIRS+=("$tmp_dir")

    wget -O "$tmp_dir/$GHIDRA_ZIP" "$GHIDRA_URL"

    if [ "$verify" = true ]; then
        local actual
        actual="$(sha256sum "$tmp_dir/$GHIDRA_ZIP" | cut -d ' ' -f 1)"
        if [ "$actual" != "$GHIDRA_SHA256" ]; then
            echo "[-] Error: Ghidra archive checksum mismatch; refusing to install it." >&2
            echo "    expected: $GHIDRA_SHA256" >&2
            echo "    actual:   $actual" >&2
            exit 1
        fi
        echo "[*] Ghidra archive checksum verified."
    else
        echo "[!] Ghidra archive from BIN_SBOM_GHIDRA_URL is installed without a checksum check."
    fi

    echo "[*] Extracting Ghidra..."
    unzip -q "$tmp_dir/$GHIDRA_ZIP" -d "$tmp_dir/extracted"

    if [ ! -d "$tmp_dir/extracted/$GHIDRA_DIRNAME" ]; then
        echo "[-] Error: archive did not contain '$GHIDRA_DIRNAME'." >&2
        exit 1
    fi

    # ghidra_project is deliberately absent: bin-sbom's cli.py creates a private one
    # per run, because bin_preprocessor.clean_ghidra_project() wipes whatever it finds.
    rm -rf "$BSG_DIR/tools/ghidra/$GHIDRA_DIRNAME"
    mkdir -p "$BSG_DIR/tools/ghidra"
    mv "$tmp_dir/extracted/$GHIDRA_DIRNAME" "$BSG_DIR/tools/ghidra/$GHIDRA_DIRNAME"
    chmod +x "$BSG_DIR/tools/ghidra/$GHIDRA_DIRNAME/support/analyzeHeadless"

    echo "[+] Ghidra installed at 'Binary_SBOM_Generator/tools/ghidra/$GHIDRA_DIRNAME'."
}

check_component_db() {
    if component_db_present; then
        echo "[*] bin-sbom component database already present."
        return
    fi

    # Not an error: the rest of the setup does not need the database, and scans that
    # use bin-sbom stop with the same guidance until it exists.
    cat >&2 <<EOT
[!] Warning: no bin-sbom component database is installed.

    BOLT does not distribute one. Scans with the default generator (bom-blint) work
    without it, but scans with --binary-sbom bin-sbom stop before scanning until you
    build it from the OSS sources you list in
    Binary_SBOM_Generator/osscollector/repolist.txt
    (see "Build the component database" in README.md).
EOT
}

if [ ! -d "$BSG_DIR" ]; then
    echo "[-] Error: 'Binary_SBOM_Generator' not found in '$ROOT_DIR'." >&2
    echo "    Run this script from the root of a BOLT checkout." >&2
    exit 1
fi

mkdir -p "$BSG_DIR/tools"

fetch_ghidra
check_component_db

if component_db_present; then
    echo "[*] bin-sbom run-time data is ready."
else
    echo "[*] Ghidra is ready; the bin-sbom component database still needs to be built."
fi
