#!/usr/bin/env sh
# SecureGitX installer
# Usage: curl -fsSL https://raw.githubusercontent.com/peroxile/SecureGitX/main/scripts/install.sh | sh
set -eu

REPO="https://github.com/peroxile/SecureGitX"
PACKAGE="securegitx"
MIN_PYTHON="3.10"

_err() { printf '[error] %s\n' "$1" >&2; exit 1; }
_info() { printf '[info]  %s\n' "$1"; }
_ok()   { printf '[ok]    %s\n' "$1"; }

# Locate python3 >= 3.10
find_python() {
    for cmd in python3 python3.12 python3.11 python3.10; do
        if command -v "$cmd" >/dev/null 2>&1; then
            ver=$("$cmd" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo "0.0")
            major=$(echo "$ver" | cut -d. -f1)
            minor=$(echo "$ver" | cut -d. -f2)
            if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
                echo "$cmd"
                return 0
            fi
        fi
    done
    return 1
}

PYTHON=$(find_python) || _err "Python >= $MIN_PYTHON is required. Install it from python.org."
_ok "Found Python: $($PYTHON --version)"

# Verify pip is available
"$PYTHON" -m pip --version >/dev/null 2>&1 || _err "pip not found. Install pip first."

# Install
_info "Installing $PACKAGE from $REPO ..."
"$PYTHON" -m pip install --quiet "git+${REPO}.git"

# Verify
if command -v securegitx >/dev/null 2>&1; then
    _ok "Installed: $(securegitx --version)"
    printf '\nQuick start:\n'
    printf '  securegitx init          # create config\n'
    printf '  securegitx hook install  # install pre-commit hook\n'
    printf '  securegitx scan --staged # manual scan\n'
else
    _err "Installation succeeded but 'securegitx' command not found. Check that pip's bin directory is in your PATH."
fi