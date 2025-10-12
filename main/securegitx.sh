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
ENFORCE_SAFE_EMAIL=true   # Hey buddy you can actually turn this off depending on your preference.

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
"*.json.key"
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
"*.seed"
"*.keystore"
"*.mnemonic"
"*.contract"
".chain/"

)

# Excluded directories (This script won't include the following DIRS:)

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
"ganache-db/"
"hardhat-network/"
".idea"
".vscode"
)
EOF

log_success "Created default configuration: $CONFIG_FILE"


}


# Phase 1: AUTHENTICATION - Verify User Identity 

check_git_repo() {
    if ! git rev-parse --git-dir > /dev/null 2>&1; then 
        log_error "Not a git repository. Please run 'git init' first."
        exit 1
    fi
}

check_user_identity() {
        log_step "PHASE 1: AUTHENTICATION - Verifying User Identity"
    separator


    local name=$(git config user.name 2>/dev/null || echo "")
    local email=$(git config user.email 2>/dev/null || echo "")


    # Check if name is configured 

    if [[ -z "$name" ]]; then
        log_error "Git user.name is not configured!"
        echo ""
        echo "Your commits need an identity. Set it with:"
        echo " git config user.name \"Your Name\""
        echo  ""
        echo "Or globally;"
        echo " git config --global user.name \"Your Name\""
        exit 1
    fi

        # Check if email is configured 
if [[ -z "$email" ]]; then
    log_error "Git user.email is not configured!"
    echo ""
    echo "Your commits need an email. Set it with:"
    echo " git config user.email \"you@example.com\""
    echo ""
    echo "Or globally:"
    echo " git config --global user.email \"you@example.com\""
    exit 1
fi

log_success "Identity verified: $name <$email>"


# check_email_safety "$email"      
check_email_safety "$email"

}


check_email_safety() {             
    local current_email=$1

    if [[ "$current_email" == *"@users.noreply.github.com" ]]; then
        log_success "Email safety protected  (Github no-reply)"  
        return
    fi

    log_warning "Personal email detected: $current_email"

    if [[ "$ENFORCE_SAFE_EMAIL" == "true" ]]; then
        echo ""
        echo "Safety recommendation: Use Github's no-reply email"
        echo "Safe email: $SAFE_EMAIL"
        echo ""
        echo -n "Switch to safe email? [Y/n]"
        read -r response 
        response=${response:-Y}

        if [[ "$response" =~ ^[Yy]$ ]]; then
            git config user.email "$SAFE_EMAIL"
            log_success "Switched to safe email: $SAFE_EMAIL"
        else
            log_info "Keep current email (Email safety not enforced)"
        fi
    fi

}

 