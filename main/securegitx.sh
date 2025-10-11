#!/bin/bash

##################
# SecureGitx - SecureGitX is a robust, Bash-based workflow automation script designed to enhance security for developers.
# Version: 1.1.0
# Workflow: Auth => Scan => Secure Commit
##################

set -euo pipefail 
set -x

# Colors for output 

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' 


# Configuraton: Default configuration 
CONFIG_FILE=".securegitx_config"
GITIGNORE_MARKER="# Injected by SecureGitX"
SCRIPT_VERSION="1.1.0"


# Utility Functions 

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_step() {
    echo -e "${CYAN}▶${NC} $1"
}

separator() {
    echo "────────────────────────────────────────────────────────────────"
}


# Configuration Management

load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        return 0
    fi
    return 1
}

create_default_config() {
    local github_username=$(git config --global user.name 2>/dev/null || echo "username")
    github_username=$(echo "$github_username" | tr '[:upper]' '[:lower] ' | tr ' ' '-' )

    cat > "$CONFIG_FILE" << EOF 

# SecureGitx Configuration (v${SCRIPT_VERSION})
# This file is automatically ignored by git

# Safe email configuration
SAFE_EMAIL="${github_username}@users.noreply.github.com"
ENFORCE_SAFE_EMAIL=true

# Sensitive file patterns to scan
SCAN_PATTERNS=(
"*.env"
"*.env.*"
"*.key"
"*.pem"
"*.p12"
"*.pfx"
"*.keystore"
".secrets/"
"secrets/"
"secrets."
"private.*"
"credentials.*"
".credentials"
"config.json"
".config.json"
"*.password"
"id_rsa"
"id_dsa"
"*.ppk"
"*.log"
"*.sql"
"*.sqlite"
"*.db"
"*.database"
"database"
)

# Excluded directories (This script won't the following:)

EXCLUDE_DIRS=(

".git"
"node_modules"
"vendor"
"venv"
".venv"
"dist"
"*.dist"
"build"
"__pycache__"
".idea"
".vscode"
)
EOF

log_success "Created default configuration: $CONFIG_FILE"


}