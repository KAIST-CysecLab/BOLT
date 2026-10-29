# Created by KimSeoYe on 2025-05-28

#!/usr/bin/env bash
set -euo pipefail

mkdir -p build
cd build

TMP_DIR=tmp # Delete this line later
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
if python3 -c "import bom_blint" &> /dev/null; then
    echo "bom_blint is already installed."
else
    echo "Installing bom_blint..."
    pip3 install ../bom_blint-2.4.2-py3-none-any.whl
    if [ $? -eq 0 ]; then
        echo "Successfully installed bom_blint."
    else
        echo "Failed to install bom_blint."
        exit 1
    fi
fi
# bin-sbom is optional: it is only used with "--binary-sbom bin-sbom", and needs a
# prebuilt component database plus Ghidra at scan time. A failure here must not stop
# the bolt build.
if [ "${SKIP_BIN_SBOM:-0}" = "1" ]; then
    echo "[*] Skipping bin-sbom (SKIP_BIN_SBOM=1)."
elif python3 -c "import bin_sbom" &> /dev/null; then
    echo "bin-sbom is already installed."
elif [ -d ../Binary_SBOM_Generator ]; then
    echo "Installing bin-sbom..."
    if pip3 install ../Binary_SBOM_Generator; then
        echo "Successfully installed bin-sbom."
        echo "    Set BIN_SBOM_DB to the prebuilt component database before using it."
    else
        echo "[!] Failed to install bin-sbom; '--binary-sbom bin-sbom' will be unavailable."
    fi
else
    echo "[!] Binary_SBOM_Generator not found; skipping bin-sbom."
fi

echo "[*] Building bolt ..."
go build -o bolt ../cmd/trivy
echo "[*] SUCCESS: ./build/bolt"

if ! echo ":$PATH:" | grep -q ":$INSTALL_DIR:"; then
	echo
	echo "[!] $INSTALL_DIR is not included in PATH. Insert following line into ~/.bashrc"
	echo "      export PATH=\"$INSTALL_DIR:\$PATH\""
	echo
fi

# Clearing tmp directory
rm -rf $TMP_DIR