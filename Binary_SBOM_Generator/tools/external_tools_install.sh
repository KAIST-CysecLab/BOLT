#!/bin/bash
# Check if the operating system is Debian-based
if ! command -v apt-get &> /dev/null; then
    echo "This script can only be run on Debian-based operating systems (Ubuntu, Debian, etc.)."
    exit 1
fi


# Install Ghidra
mkdir -p ./ghidra/ghidra_project
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2.1_build/ghidra_11.2.1_PUBLIC_20241105.zip
unzip ghidra_11.2.1_PUBLIC_20241105.zip -d ghidra
rm ghidra_11.2.1_PUBLIC_20241105.zip


# Install Ctags
sudo apt-get install -y universal-ctags
