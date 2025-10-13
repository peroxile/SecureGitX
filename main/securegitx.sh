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

# Auto .gitignore management 
AUTO_GITIGNORE=true

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

 check_branch_state() {
    log_step "Checking branch state..."

    # Check for detached HEAD
    if ! git symbolic-ref -q HEAD > /dev/null; then  
        log_error "Detached HEAD state detected!"
        echo ""
        echo "You're not on a branch. Your commits may be lost."
        echo "Create a branch first:"
        echo " git checkout -b my-feature-branch"
        echo ""
        echo "Or checkout an existing branch:"
        echo " git checkout main"
        exit 1
    fi

    local current_branch=$(git branch --show-current)
    log_success "On branch: $current_branch"
 }


# Phase 2: SCANNING - Repository Security Scan

detect_project_type() {
    local project_type="generic"

    if [[ -f "package.json" ]];then
        project_type="node"
    elif [[ -f "requirements.txt" ]] || [[ -f "setup.py" ]] || [[ -f "pyproject.toml" ]]; then
        project_type=::"python"
    elif [[ -f "go.mod" ]]; then
        project_type="go"
    elif [[ -f "Cargo.toml" ]]; then
        project_type="rust"
    elif [[ -f "pom.xml" ]] || [[ -f "build.gradle" ]]; then
        project_type="java"
    elif [[ -f "composer.json" ]]; then
        project_type="php"
    fi

    echo "$project_type"
}

get_gitignore_template() {
    local project_type=$1

    local common_ignores="
    # OS generated files 
    .DS_Store
    .DS_Store?
    ._*
    .Spotlight-V100
    .Trashes
    ehthumbs.db
    Thumbs.db
    *~


    # IDE and Editors files
    .vscode/
    .idea/
    *.swp
    *.swo
    *.swn
    .project
    .settings/
    *.sublime-*


    # SecureGitx configuration
    $CONFIG_FILE

    # Security sesnsitive files
*.env.*
*.key
*.pem
*.p12
*.pfx
*.ppk
*.psk
*.keystore
.secrets/
secrets/
secrets.
private.*
credentials.*
.credentials
config.json
.config.json
*.json.key
*.password
id_rsa
id_dsa
*.ppk
*.log
*.sql
*.sqlite
*.db
*.database
database
*.seed
*.keystore
*.mnemonic
*.contract
.chain/
config.local.*    
"

    case $project_type in
        node)
            echo "$common_ignores
# Node.js
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*
.npm
.eslintcache
.yarn-integrity
dist/
build/"
    ;;
    python)
        echo "$common_ignores
# Python
__pychache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
ENV/
*.egg-info/
dist/
build/
*.log
.pytest_cache/"
            ;;
        go)
            echo "$common_ignores
# Go
*.exe
*.exe~
*.dll
*.so
*.dylib
*.test
*.out
vendor/
go.work"
        ;;
        php)
            echo "$common_ignores
# PHP
vendor/
composer.lock
*.log
.phpunit.result.cache
"
            ;;
        *)

           echo "$common_ignores"
            ;;
    esac            
            
}


ensure_gitgnore() {
    if [[ "$AUTO_GITIGNORE" != "true" ]]; then
        return
    fi

    if [[ -f ".gitignore" ]]; then
        if grep -q "$GITIGNORE_MARKER" .gitignore 2>/dev/null; then
            log_success ".gitignore managed by SecureGitx"
        else
            log_info ".gitignore exists (user-managed)"
        fi

        # Ensure config file is ignored 
        if ! grep -q "^$CONFIG_FILE$" .gitignore 2>/dev/null; then
            echo "" >> .gitignore
            echo "# SecureGitX" >> .gitignore
            echo "$CONFIG_FILE" >> .gitignore
            log_success "Added $CONFIG_FILE to .gitignore"
        fi
        return
    fi

    local project_type=$(detect_project_type)
    log_info "Creating .gitignore for $project_type project..."

    echo "$GITIGNORE_MARKER" > .gitignore
    get_gitignore_template "$project_type" >> .gitignore

    log_success "Created comprehensive .gitignore"
}

scan_sensitive_files() {
    log_step "PHASE 2: SCANNING - Security Repository Scan"
    separator

    log_info "Scanning for sensitive files in repository..."


    local found_issues=0
    local exclude_args=""

    # Build exclude arguments
    for dir in "${EXCLUDE_DIRS[@]}"; do 
        exclude_args="$exclude_args -path ./$dir -prune -o"
    done

    for pattern in "${SCAN_PATTERNS[@]}"; do
        local files=$(eval "find . $exclude_args -name '$pattern' -type f -print" 2>/dev/null)

        if [[ -n "$files" ]]; then
            # Check if files are in git 
            while IFS= read -r file; do 
                if git ls-files --error-unmatch "$file" > /dev/null 2>&1; then
                    log_warning "Tracked sensitive file: $file"
                        found_issues=$((found_issues + 1))
                fi
            done <<< "$files"
        fi
    done

    if [[ $found_issues -gt 0 ]]; then
        return 1
    fi

    log_success "No sensitive files detected in repository"
    return 0
    
}

