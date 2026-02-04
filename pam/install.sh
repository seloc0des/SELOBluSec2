#!/usr/bin/env bash
# BluSec 2.0 — PAM integration installer
#
# Usage:
#   sudo ./pam/install.sh [--uninstall]
#
# What it does (install):
#   1. Installs blusec2 system-wide via pip
#   2. Copies the PAM config snippet to /etc/pam.d/blusec2-auth
#   3. Verifies the blusec2-pam script is on PATH
#
# What it does (uninstall):
#   1. Removes the PAM config from /etc/pam.d/
#   2. Uninstalls the blusec2 pip package
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PAM_CONF="/etc/pam.d/blusec2-auth"
PAM_BIN="blusec2-pam"

red()   { printf '\033[1;31m%s\033[0m\n' "$*"; }
green() { printf '\033[1;32m%s\033[0m\n' "$*"; }
info()  { printf '  -> %s\n' "$*"; }

# ── Root check ──────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    red "Error: This script must be run as root (sudo)."
    exit 1
fi

# ── Uninstall ───────────────────────────────────────────────────────
if [[ "${1:-}" == "--uninstall" ]]; then
    echo "Uninstalling BluSec2 PAM integration..."

    if [[ -f "$PAM_CONF" ]]; then
        rm -f "$PAM_CONF"
        info "Removed $PAM_CONF"
    else
        info "$PAM_CONF not found (already removed)"
    fi

    if python3 -m pip show blusec2 &>/dev/null; then
        python3 -m pip uninstall -y blusec2
        info "Uninstalled blusec2 pip package"
    else
        info "blusec2 pip package not installed"
    fi

    green "PAM integration removed."
    echo
    echo "Note: /etc/blusec2 config directory was NOT removed."
    echo "Delete it manually if you no longer need it:"
    echo "  sudo rm -rf /etc/blusec2"
    exit 0
fi

# ── Install ─────────────────────────────────────────────────────────
echo "Installing BluSec2 PAM integration..."
echo

# Step 1: Install the package system-wide
info "Installing blusec2 package..."
python3 -m pip install "$PROJECT_DIR"
echo

# Step 2: Verify the PAM script is available
if ! command -v "$PAM_BIN" &>/dev/null; then
    red "Error: $PAM_BIN not found on PATH after install."
    red "Ensure pip's bin directory is in the system PATH."
    exit 1
fi

PAM_BIN_PATH="$(command -v "$PAM_BIN")"
info "Found $PAM_BIN at $PAM_BIN_PATH"

# Step 3: Copy PAM config
cp "$SCRIPT_DIR/blusec2-auth" "$PAM_CONF"
chmod 644 "$PAM_CONF"
info "Installed PAM config to $PAM_CONF"

echo
green "PAM integration installed successfully!"
echo
echo "Next steps:"
echo "  1. Pair a device (if not done already):"
echo "     sudo blusec2 --mode setup --device-address AA:BB:CC:DD:EE:FF --device-id DEVICE-001"
echo
echo "  2. Enroll a user:"
echo "     sudo blusec2 --mode enroll --user \$(whoami)"
echo
echo "  3. Enable for a service (e.g. sudo):"
echo "     Add this line to /etc/pam.d/sudo (before pam_unix):"
echo "     auth  [success=1 default=ignore]  pam_exec.so  expose_authtok  $PAM_BIN_PATH"
echo
echo "  4. Test:"
echo "     sudo -k && sudo echo 'BluSec2 works!'"
