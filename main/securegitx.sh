#!/bin/bash

##################
# SecureGitx - SecureGitX is a robust, Bash-based workflow automation script designed to enhance security for developers.
# Version: 1.1.0
# Workflow: Auth => Scan => Secure Commit
##################

set -euo pipefail 
# set -x

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
        # shellcheck disable=SC1090
        source "$CONFIG_FILE"
        return 0
    fi
    return 1
}

create_default_config() {
    local github_username
    github_username=$(git config --global user.name 2>/dev/null || echo "username")
    github_username=$(echo "$github_username" | tr '[:upper]' '[:lower]' | tr ' ' '-' )

    cat > "$CONFIG_FILE" << EOF 

# SecureGitx Configuration (v${SCRIPT_VERSION})
# This file is automatically ignored by git

# Safe email configuration
SAFE_EMAIL="${github_username}@users.noreply.github.com"
ENFORCE_SAFE_EMAIL=false 


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
"*-secret/"
"private.*"
"private/"
"credentials.*"
".credentials"
"credentials/"
"creds/"
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

    local name
    name=$(git config user.name 2>/dev/null || echo "")
    local email
    email=$(git config user.email 2>/dev/null || echo "")


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

}


check_email_safety() {             
    local current_email=$1
    local force_prompt=${2:-false}

    if [[ "$current_email" == *"@users.noreply.github.com" ]]; then
        log_success "Email safety protected  (Github no-reply)"  
        return
    fi

    # Only prompt if enabled OR --safe-email flag
    if [[ "$ENFORCE_SAFE_EMAIL" == "true" ]] || [[ "$force_prompt" == "true" ]]; then
        log_warning "Personal email detected: $current_email"
        echo ""
        echo "Safety recommendation: "
        echo "   Using a personal email exposes it in git history forever."
        echo "   Consider using GitHub's no-reply email instead."
        echo ""
        echo " Your no-reply email: $SAFE_EMAIL"
        echo ""
        echo -n "Switch to safe email? [y/N]"
        read -r response 
        response=${response:-N}

        if [[ "$response" =~ ^[Yy]$ ]]; then
            git config user.email "$SAFE_EMAIL"
            log_success "Switched to safe email: $SAFE_EMAIL"
        else
            log_info "Keep current email: $current_email"
        fi
    else
        log_info "Email: $current_email"
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

    local current_branch
    current_branch=$(git branch --show-current)
    log_success "On branch: $current_branch"
 }


# Phase 2: SCANNING - Repository Security Scan

detect_project_type() {
    local project_type="generic"

    if [[ -f "package.json" ]];then
        project_type="node"
    elif [[ -f "requirements.txt" ]] || [[ -f "setup.py" ]] || [[ -f "pyproject.toml" ]]; then
        project_type="python"
    elif [[ -f "go.mod" ]]; then
        project_type="go"
    elif [[ -f "Cargo.toml" ]]; then
        project_type="rust"
    elif [[ -f "pom.xml" ]] || [[ -f "build.gradle" ]]; then
        project_type="java"
    elif [[ -f "composer.json" ]]; then
        project_type="php"
    fi

# If still generic, scan actual files in repo
   if [[ "$project_type" == "generic" ]]; then
        # Check staged files (what user is committing)
        local staged_files
        staged_files=$(git ls-files 2>/dev/null || find . -type f -name "*.py" -o -name "*.js" -o -name "*.go" 2>/dev/null | head -10)

        # Count file extensions
        local py_count js_count go_count rs_count
        py_count=$(echo "$staged_files" | grep -c '\.py$' || echo 0)
        js_count=$(echo "$staged_files" | grep -c '\.(js|ts|jsx|tsx)$' || echo 0)
        go_count=$(echo "$staged_files" | grep -c '\.go$' || echo 0)
        rs_count=$(echo "$staged_files" | grep -c '\.rs$' || echo 0)

        # Determine by file count 
        if [[ $py_count -gt 2 ]]; then
            project_type="python"
        elif [[ $js_count -gt 2 ]]; then
            project_type="node"
        elif [[ $go_count -gt 2 ]]; then 
            project_type="go"
        elif [[ $rs_count -gt 2 ]]; then
            project_type="rust"
        fi
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

# Security sensitive files
*.env
*.env.*
.env.local
*.key
*.pem
*.p12
*.pfx
*.ppk
*.keystore
.secrets/
secrets/
secret.*
*-secrets/
*-secret/
private/
private.*
credentials/
credentials.*
.credentials
creds/
config.json
.config.json
*.json.key
*.password
id_rsa
id_dsa
*.log
*.sql
*.sqlite
*.db
*.database
database
*.seed
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
build/
.next
out/"
    ;;
    python)
        echo "$common_ignores
# Python
__pychache__/
*.py[cod]
*\$py.class
*.so
.Python
env/
venv/
.venv/
ENV/
*.egg-info/
dist/
build/
*.log
.pytest_cache/
.mypy_cache/
.tox/"
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
go.work
go.sum"
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
        java)
            echo "$common_ignores
# Java
    *.class
*.jar
*.war
*.ear
target/
.gradle/
build/
*.log
.project"
        ;;
        rust)
            echo "$common_ignores
# Rust
target/
Cargo.lock
**/*.rs.bk
*.pdb"
        ;;
        *)

           echo "$common_ignores"
        ;;
    esac            
            
}


ensure_gitignore() {
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
        if ! grep -q  "^$CONFIG_FILE$" .gitignore 2>/dev/null; then
        
            {
                echo ""
                echo "# SecureGitX"
                echo "$CONFIG_FILE" 
            } >> .gitignore
        log_success "Added $CONFIG_FILE to .gitignore"

        fi
        return
    fi

    local project_type
    project_type=$(detect_project_type)
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
        local files
        files=$(eval "find . $exclude_args -name '$pattern' -type f -print" 2>/dev/null)

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


# Phase 3: VALIDATION - Pre Commits Checks 

scan_staged_files() {
    log_step "PHASE 3: VALIDATION - Pre-Commit Security Check"
    separator

    log_info "Checking staged files..."

    local staged_files
    staged_files=$(git diff --cached --name-only)

    if [[ -z "$staged_files" ]]; then
        log_warning "No files staged for commit"
        return 0 
    fi

    log_info "Staged files: $(echo "$staged_files" | wc -l | tr -d ' ') file(s)"

    echo ""
    log_info "Staged Files:"
    echo "$staged_files" | awk '{printf " • %s\n", $0}'


    local issues=0


    while IFS= read -r file; do 
        for pattern in "${SCAN_PATTERNS[@]}"; do 
            if [[ "$file" == "$pattern" ]] || [[ "$file" == *"/$pattern"* ]]; then
                log_warning "Sensitive file staged: $file"
                issues=$((issues + 1))
            fi
        done
    done <<< "$staged_files"

    if [[ $issues -gt 0 ]];then
        return 1 
    fi

    log_success "All staged files passed security check"
    return 0 

}


# Phase 4: SECURE COMMIT - Final Execution 

perform_secure_commit() {
    log_step "PHASE 4: SECURE COMMIT - Finalizing"
    separator

    local commit_message=$1

    log_info "Security checks passed. Ready to commit"
    echo ""
    echo " Commit details:"
    echo " Author: $(git config user.name) <$(git config user.email)>"
    echo " Branch: $(git branch --show-current)" 
    echo " Files: $(git diff --cached --name-only | wc -l | tr -d ' ') staged"
    echo " Message: \"$commit_message\""
    echo " "


    if git commit -m "$commit_message"; then
        log_success "Commit successful!"
        echo ""
        echo "Latest commit:"
        git log -1 --oneline
        echo ""
        log_success "SecureGitX workflow complete - All good!"
    else 
        log_error "Commit failed" 
        exit 1
    fi
}


## Main Workflow 


show_banner() {
    cat << "EOF"
    
  ____                         _______     __      _   _
 / __|\____ ___ _   _ _ __ ___|   ____( ) |  |__  \ \_/ /
 \___ \ / _ \/ __| | | | '__/ _ \|  _ _ | |  _ _\  \/+\/
  ___) |  __/ (__| |_| | | |  __/|__| | | |  |___  / /\ \
 |____/ \___|\___|\__,_|_|  \___|_____|_|_|______|/_/  \_\
                                        
EOF
    echo "  Git Security and Safety Automation v${SCRIPT_VERSION}"
    echo " Workflow: Auth => Scan => Validate => Secure Commit"
    separator

}

main() {
    local commit_message=""
    local force_safe_email=false

    while [[ $# -gt 0 ]]; do 
        case $1 in 
            --safe-email)
                force_safe_email=true
                shift
                ;;
            --help|-h)
                show_banner
                echo "Usage $0 [OPTIONS] [commit-message]"
                echo ""
                echo "Options:"
                echo "  --safe-email    Prompt to switch to no-reply email"
                echo " --help, h        Show this help message"
                echo ""
                echo "Examples:"
                echo "  $0             # Run security checks only"
                echo "  $0 \"feat: add authentication\" # Secure commit"
                echo " $0 --safe-email  # Email privacy check"
                exit 0
                    ;;
                *)
                    commit_message="$1"
                    shift 
                    ;;
        esac
    done

    show_banner

## Phase 1: AUTHENTICATION - Verify User Identity 

check_git_repo
log_success "Git repository detected"


# Load or create configuration
if ! load_config; then
    log_info "first run - creating configuration..."
    create_default_config
    load_config
else
    log_success "Configuration loaded"
fi

separator


separator

check_user_identity  # Check user identity

# Always check email safety (behavior controlled by force_safe_email and config)
local current_email
current_email=$(git config user.email)
check_email_safety "$current_email" "$force_safe_email"

check_branch_state  # Check branch state (not detached HEAD)

separator



## Phase 2: SCANNING - Repository Security Scan


ensure_gitignore     

separator

# Scan repository for existing sensitive files
if ! scan_sensitive_files; then 
    log_error "Security scan found issues in repository!"
    echo ""
    echo "Please review the warning before commiting."
    echo "Options:"
    echo " 1. Add files to .gitignore"
    echo " 2. Remove sensitive data from files"
    echo " 3. Use git-filter branch to clean history if already commited"
    exit 1
fi

separator



# Phase 3: VALIDATION - Pre Commits Checks 

if [[ -n "$commit_message" ]]; then
    
    if ! scan_staged_files;then
        log_error " Security issues found in staged files!"
        echo ""
        echo "Review the issues above, then take one of these actions:"
        echo "  1. Unstage the file(s): git reset HEAD <file>"
        echo "  2. Add them to .gitignore if they shouldn't be tracked"
        echo "  3. Use --no-verify to proceed anyway (not recommended)"
        exit 1
    fi

    separator


# Phase 4: SECURE COMMIT - Final Execution 

    perform_secure_commit "$commit_message"
else
    log_success "Security checks complete - repository is clean"
    echo ""
    echo "Next steps:"
    echo " 1. Stage your changes: git add <files>"
    echo " 2. Commit securely:    $0 \"your commit message\""
    echo ""
    log_info "No commit performed (no message provided)"
fi

}

main "$@"