#!/bin/bash

set -e

if [[ $EUID -eq 0 ]]; then
    echo "[!] Run this installer without sudo."
    echo "    ./install.sh"
    exit 1
fi

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMMAND_PATH="/usr/local/bin/fangrecon"
SUDOERS_FILE="/etc/sudoers.d/fangrecon"

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

# Configure sudo PATH if necessary
echo "[+] Checking sudo PATH..."

SUDO_PATH="$(sudo sh -c 'printf "%s" "$PATH"')"

case ":$SUDO_PATH:" in
    *:/usr/local/bin:*)
        echo "[+] /usr/local/bin is already in sudo PATH."
        ;;
    *)

        echo "[+] Adding /usr/local/bin to sudo PATH..."

        if [[ -e "$SUDOERS_FILE" || -L "$SUDOERS_FILE" ]]; then
            echo "[!] $SUDOERS_FILE already exists."
            echo "[!] Refusing to overwrite an existing sudoers configuration."
            exit 1
        fi

        SUDOERS_TEMP="$(mktemp)"

        trap 'rm -f "$SUDOERS_TEMP"' EXIT

        printf 'Defaults secure_path="%s:/usr/local/bin"\n' "$SUDO_PATH" > "$SUDOERS_TEMP"

        # Validate before installing
        sudo visudo -cf "$SUDOERS_TEMP"

        # Install dedicated sudoers configuration
        sudo install -o root -g root -m 0440 \
            "$SUDOERS_TEMP" "$SUDOERS_FILE"

        rm -f "$SUDOERS_TEMP"
        trap - EXIT

        # Verify updated PATH
        SUDO_PATH="$(sudo sh -c 'printf "%s" "$PATH"')"

        case ":$SUDO_PATH:" in
            *:/usr/local/bin:*)
                echo "[+] Sudo PATH updated successfully."
                ;;
            *)
                echo "[!] Failed to update sudo PATH."
                exit 1
                ;;
        esac
        ;;
esac

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
