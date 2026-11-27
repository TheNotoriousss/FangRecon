#!/bin/bash

set -e

if [[ $EUID -eq 0 ]]; then
    echo "[!] Run this installer without sudo."
    echo "    ./install.sh"
    exit 1
fi

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMMAND_PATH="/usr/local/bin/fangrecon"

echo "[+] Installing FangRecon..."

# Check required files
for file in requirements.txt fangrecon network-scanner.py port_scanner.py; do
    if [[ ! -f "$PROJECT_DIR/$file" ]]; then
        echo "[!] Required file missing: $file"
        exit 1
    fi
done

# Check Python
if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] Python 3 is required."
    exit 1
fi

# Check existing command before replacing anything
if [[ -e "$COMMAND_PATH" && ! -L "$COMMAND_PATH" ]]; then
    echo "[!] $COMMAND_PATH already exists and is not a symlink."
    echo "[!] Refusing to overwrite it."
    exit 1
fi

echo "[+] Checking virtual environment..."

PYTHON="$PROJECT_DIR/.venv/bin/python3"

if [[ ! -x "$PYTHON" ]]; then
    if [[ -d "$PROJECT_DIR/.venv" ]]; then
        echo "[!] Existing .venv is incomplete."
        echo "[!] Remove it manually and run the installer again."
        exit 1
    fi

    echo "[+] Creating virtual environment..."
    python3 -m venv "$PROJECT_DIR/.venv"
fi

echo "[+] Installing Python dependencies..."

"$PYTHON" -m pip install --upgrade pip
"$PYTHON" -m pip install -r "$PROJECT_DIR/requirements.txt"

echo "[+] Registering FangRecon command..."

chmod +x "$PROJECT_DIR/fangrecon"

sudo ln -sfn "$PROJECT_DIR/fangrecon" "$COMMAND_PATH"

echo
echo "[+] FangRecon installation completed!"
echo "[+] Run: sudo fangrecon --help"
