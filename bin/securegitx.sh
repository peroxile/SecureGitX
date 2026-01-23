#!/usr/bin/env bash

##################
# SecureGitX - Secure Git workflow automation 
# Workflow: Auth => Scan => Secure Commit
##################

set -euo pipefail
# set -x

# --------- Metadata & Defaults ----------
SCRIPT_VERSION="$(
  git describe --tags --abbrev=0 --exact-match 2>/dev/null \
  || echo '1.2.0'
)" 

CONFIG_FILE=".securegitx_config"
GITIGNORE_MARKER="# Injected by SecureGitX"
DEFAULT_SAFE_EMAIL_SUFFIX="@users.noreply.github.com"

# --------- Unicode / Terminal Capability ----------
support_unicode() {
  [[ "${LANG:-}" =~ UTF-8 ]] || [[ "${LC_ALL:-}" =~ UTF-8 ]]
}

if support_unicode && test -t 1; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
  OK="✓"; WARN="⚠"; ERR="✗"; INFO="ℹ"; STEP="▶"
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; NC=''
  OK="[OK]"; WARN="[WARN]"; ERR="[ERR]"; INFO="[INFO]"; STEP=">"
fi

log_info()    { printf "%b %s %s%b\n" "$BLUE" "$INFO" "$1" "$NC"; }
log_success() { printf "%b %s %s%b\n" "$GREEN" "$OK" "$1" "$NC"; }
log_warning() { printf "%b %s %s%b\n" "$YELLOW" "$WARN" "$1" "$NC"; }
log_error()   { printf "%b %s %s%b\n" "$RED" "$ERR" "$1" "$NC"; }
log_step()    { printf "%b %s %s%b\n" "$CYAN" "$STEP" "$1" "$NC"; }
separator()   { printf '%s\n' "──────────────────────────────────────────────────"; }


if ! PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    log_error "Not inside a Git repository"
    exit 1
fi

WRAPPER_DIR="$PROJECT_ROOT/wrappers"
PY_ANALYZER="$WRAPPER_DIR/securegitx_wrapper.py"

if [[ ! -f "$PY_ANALYZER" ]]; then
    log_error "Python analyzer missing at: $PY_ANALYZER"
    exit 1
fi


# ---------- Defaults that config may override ----------
SAFE_EMAIL=""
ENFORCE_SAFE_EMAIL=true
AUTO_GITIGNORE=true
SCAN_PATTERNS=(
  "*.env"
  "*.env.*"
  "*.key"
  "*.pem"
  "*.p12"
  "*.pfx"
  "*.keystore"
  ".secrets/*"
  "secrets/*"
  "private.*"
  "private/*"
  "credentials.*"
  ".credentials"
  "credentials/*"
  "creds/*"
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
  "*.seed"
  "*.mnemonic"
  "*.contract"
  ".chain/*"
)


# ---------- Utility functions ----------
_abs_path () {
    # cross-platform absolute path for a file
    local f="$1"
    if command -v realpath >/dev/null 2>&1; then
        realpath "$f" 2>/dev/null || printf '%s\n' "$f"
    elif command -v readlink >/dev/null 2>&1; then 
        readlink -f "$f" 2>/dev/null || printf "%s\n" "$f"
    else
        # fallback: naive 
        (cd "$(dirname "$f")" 2>/dev/null && printf '%s/%s\n' "$(pwd -P)" "$(basename "$f")") || printf '%s\n' "$f"
    fi
}

confirm() {
    # Returns 0 if confirmed 
    local prompt="${1:-Confirm? [y/N]: }"
    printf "%s" "$prompt"
    local ans 
    read -r ans || ans="N"
    if [[ "$ans" =~ ^[Yy] ]]; then
        return 0 
    fi 
    return 1
}

safe_trim_quotes() {
    # remove leading/trailing quotes from a value
   local v="$1"
   v="${v#\"}"; v="${v%\"}"
   v="${v#\'}"; v="${v%\'}"
   printf '%s' "$v"
}

# ---------- Config parsing (safe, no arbitrary code execution) ----------
parse_config() {
  [[ -f "$CONFIG_FILE" ]] || return 1

  local line key val
  local in_array=""
  local buf=()

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" || "$line" =~ ^# ]] && continue

    if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*\([[:space:]]*$ ]]; then
      in_array="${BASH_REMATCH[1]}"
      buf=()
      continue
    fi

    # detect array end 
    if [[ -n "$in_array" ]]; then
      if [[ "$line" =~ ^\)[[:space:]]*$ ]]; then
          # assign array
        case "$in_array" in
          SCAN_PATTERNS) SCAN_PATTERNS=("${buf[@]}") ;;
        esac
        in_array=""
        buf=()
        continue
      fi
      # collect array item lines, accepts only quoted values.
      if [[ "$line" =~ ^\"(.+)\"$ || "$line" =~ ^\'(.+)\'$ ]]; then
        buf+=("${BASH_REMATCH[1]}")
      fi
      continue
    fi

    # key=value lines
    if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=[[:space:]]*(.+)$ ]]; then
      key="${BASH_REMATCH[1]}"
      val="${BASH_REMATCH[2]%%#*}"
    # strip any trailing comment
      val="$(safe_trim_quotes "$val")"
      case "$key" in
        SAFE_EMAIL) SAFE_EMAIL="$val" ;;
        ENFORCE_SAFE_EMAIL) ENFORCE_SAFE_EMAIL="$val" ;;
        AUTO_GITIGNORE) AUTO_GITIGNORE="$val" ;;
      esac
    fi
  done < "$CONFIG_FILE"
}

create_default_config() {
    separator
    log_info "Creating default configuration: $CONFIG_FILE"

    # use default safe email from global Git name if available 
    local github_username
    github_username=$(git config --global user.name 2>/dev/null || echo "username" )
    github_username=$(echo "$github_username" | tr '[:upper:]' '[:lower]' | tr ' ' '-')
    SAFE_EMAIL="${github_username}${DEFAULT_SAFE_EMAIL_SUFFIX}"

    cat > "$CONFIG_FILE" << EOF 
# SecureGitX Configuration (v${SCRIPT_VERSION})
# This file is automatically ignored by git
SAFE_EMAIL="$SAFE_EMAIL"
ENFORCE_SAFE_EMAIL=true
AUTO_GITIGNORE=true

SCAN_PATTERNS=(
"*.env"
"*.env.*"
"*.key"
"*.pem"
"*.p12"
"*.pfx"
"*.keystore"
".secrets/*"
"secrets/*"
"private.*"
"private/*"
"credentials.*"
".credentials"
"credentials/*"
"creds/*"
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
"*.seed"
"*.mnemonic"
"*.contract"
".chain/*"
)

EXCLUDE_DIRS=(
".git"
"node_modules"
"vendor"
"venv"
".venv"
"dist"
"build"
"__pycache__"
"ganache-db"
"hardhat-network"
".idea"
".vscode"
)
EOF

log_success "Created default configuration: $CONFIG_FILE"
} 


# PHASE 1: AUTHENTICATION - Verifying User Identity

# Git check
check_git_repo() {
    if ! git rev-parse --git-dir >/dev/null 2>&1; then
        log_error "Not a git repository. Run 'git init' first."
        exit 1 
    fi
    log_success "Git repository detected"
}

check_user_identity() {
    log_step "PHASE 1: AUTHENTICATION - Verifying User Identity"
    separator
    local name email
    name=$(git config user.name 2>/dev/null || echo "")
    email=$(git config user.email 2>/dev/null || echo "")
    if [[ -z "$name" ]]; then
        log_error " user.name is not configured"
        log_info "Set with: git config user.name \"Your Name\""
        log_info "Or globally; git config --global user.name \"Your Name\""
        exit 1
    fi
    if  [[ -z "$email" ]]; then
        log_error "Git user.email is not configured"
        log_info "Set with: git config user.email \"you@example.com\""
        log_info "Or globally: git config --global user.email \"you@example.com\""
        exit 1
    fi
    log_success "Identity verified: $name <$email>"
}


check_email_safety() {             
    local current_email=$1
    local force_prompt=${2:-false}
    
    if [[ -z "$SAFE_EMAIL" ]]; then
        # compute fallback
        local gh_user
        gh_user=$(git config --global user.name 2>/dev/null || echo "username")
        gh_user=$(echo "$gh_user" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
        SAFE_EMAIL="${gh_user}${DEFAULT_SAFE_EMAIL_SUFFIX}"
    fi

    if [[ "$current_email" == *"$DEFAULT_SAFE_EMAIL_SUFFIX" || "$current_email" == *"@users.noreply.github.com" ]]; then
        log_success "Email safety protected  (Github no-reply)"  
        return 0
    fi

    if [[ "$ENFORCE_SAFE_EMAIL" == "true" ]] || [[ "$force_prompt" == "true" ]]; then
    printf "\nRecommendation: Use GitHub no-reply email to protect your identity.\n"
    printf "Steps:\n"
    printf "  1. Go to GitHub → Settings → Emails → 'Keep my email address private'\n"
    printf "  2. Copy your GitHub no-reply email (username@users.noreply.github.com)\n"
    printf "  3. Set locally with: git config user.email \"username@users.noreply.github.com\"\n\n"
else
    log_info "Email: $current_email"
fi

}

 check_branch_state() {
    log_step "Checking branch state..."

    # Check for detached HEAD
    if ! git symbolic-ref -q HEAD > /dev/null 2>&1; then  
        log_error "Detached HEAD state detected. Checkout a branch first."
        exit 1
    fi 
    local current_branch
    current_branch=$(git branch --show-current)
    log_success "On branch $current_branch"
 }


# Phase 2: SCANNING - Repository Security Scan

detect_project_type() {
    local project_type="generic"

    if [[ -f "package.json" ]];then project_type="node"; fi 
    if [[ -f "requirements.txt" || -f "setup.py" ]] || [[ -f "pyproject.toml" ]]; then project_type="python"; fi
    if [[ -f "go.mod" ]]; then project_type="go"; fi
    if [[ -f "Cargo.toml" ]]; then project_type="rust"; fi
    if [[ -f "pom.xml" ||  -f "build.gradle" ]]; then  project_type="java"; fi
    if [[ -f "composer.json" ]]; then  project_type="php"; fi

# If still generic, inspect some tracked file extensions 
    if [[ "$project_type" == "generic" ]]; then  
      if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
            local counts
        # count top extensions among tracked files (limit scanning) 
        counts=$(git ls-files | awk -F. '/\./ {print $NF}' | sort | uniq -c | sort -rn | head -10 || true)
        if echo "$counts" | grep -q '^ *[0-9]\+ .*py'; then project_type="python"; fi
        if echo "$counts" | grep -q '^ *[0-9]\+ .*\\(js\\|ts\\|jsx\\)'; then project_type="node"; fi
        if echo "$counts" | grep -q '^ *[0-9]\+ .*go'; then project_type="go"; fi 
        if echo "$counts" | grep -q '^ *[0-9]\+ .*rs'; then project_type="rust"; fi
      fi 
    fi

    printf '%s' "$project_type"
}

get_gitignore_template() {
    local project_type="$1"
    local base_ignores="# OS generated files 
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db
*~

# IDE / Editors 
.vscode/
.idea/
*.swp
*.swo
*.swn
.project
.settings/
*.sublime-*
# SecureGitX configuration
$CONFIG_FILE"

# Security patterns (Only what's relevant to the project type)
    local security_base="
# Security sensitive files (common)
*.env
*.env.*
.env.local
*.key
*.pem
id_rsa
id_dsa
*.ppk
config.local.*"

    case $project_type in
        node)
           cat <<EOF
$base_ignores
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
out/
$security_base
*.json.key
.secrets/
credentials/
EOF
    ;;
    python)
        cat <<EOF 
$base_ignores
# Python
__pycache__/
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
.tox/
$security_base
*.db
*.sqlite
EOF
        ;;
        go)
            cat <<EOF 
$base_ignores
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
go.sum
$security_base
EOF
        ;;
        rust)
            cat <<EOF
$base_ignores
# Rust
target/
Cargo.lock
**/*.rs.bk
*.pdb
$security_base
EOF
        ;;
        java)
            cat <<EOF 
$base_ignores
# Java
*.class
*.jar
*.war
*.ear
target/
.gradle/
build/
*.log
.classpath
.project
credentials.*
*.keystore
*.p12
*.pfx
$security_base
EOF
        ;;
        php)
            cat <<EOF
$base_ignores
# PHP
vendor/
composer.lock
*.log
.phpunit.result.cache
$security_base
EOF
        ;;
        generic|*)
            cat <<EOF 
$base_ignores
$security_base

# Common build directories 
dist/
build/
target/
node_modules/
vendor/
wrapper

# Additional security patterns
.secrets/
secrets/
secrets.*
*-secrets/
*-secret/
private/
private.*
credentials/
credentials.*
.credentials
creds/
*.keystore
*.p12
*.pfx
*.ppk
*.mnemonic
*.contract
.chain/
EOF
        ;;
    esac                       
}


ensure_gitignore() {
    if [[ "$AUTO_GITIGNORE" != "true" ]]; then
        log_info "AUTO_GITIGNORE disabled by config"
        return 0
    fi

  if [[ -f ".gitignore" ]]; then
    if grep -qF "$GITIGNORE_MARKER" .gitignore 2>/dev/null; then
      log_success ".gitignore managed by SecureGitX"
      return 0
    else
      # ensure config file is ignored
      if ! grep -qFx "$CONFIG_FILE" .gitignore 2>/dev/null; then
        {
          echo ""
          echo "# SecureGitX"
          echo "$CONFIG_FILE"
        } >> .gitignore
        log_success "Added $CONFIG_FILE to .gitignore"
      else
        log_info ".gitignore exists and is user-managed"
      fi
      return 0
    fi
  fi


    local project_type
    project_type=$(detect_project_type)
    log_info "Creating .gitignore for $project_type project..."
    {
        echo "$GITIGNORE_MARKER" > .gitignore
        get_gitignore_template "$project_type"
    }  >> .gitignore
    log_success "Created comprehensive .gitignore"
}


# PHASE 2: SCANNING - Security Repository Scan
#build a find expression combining patterns

scan_sensitive_files() {
    log_step "PHASE 2: SCANNING - Security Repository Scan"
    separator
    log_info "Scanning tracked files for sensitive patterns..."

    local found_issues=0

    while IFS= read -r file; do
        for pattern in "${SCAN_PATTERNS[@]}"; do
            case "$file" in
                $pattern)
                    log_warning "Tracked sensitive file: $file"
                    found_issues=$((found_issues + 1))
                    ;;
            esac
        done
    done < <(git ls-files)

    if [[ $found_issues -gt 0 ]]; then
        log_error "Found $found_issues tracked sensitive file(s)"
        return 1
    fi

    log_success "No sensitive tracked files detected in repository"
    return 0
}


scan_staged_files() {
    log_step "PHASE 3: VALIDATION - Pre-Commit Security Check"
    separator
    log_info "Checking staged files..."

    mapfile -t staged_files < <(git diff --cached --name-only 2>/dev/null || true)

    if [[ ${#staged_files[@]} -eq 0 ]]; then
        log_warning "No files staged for commit"
        return 2
    fi

    log_info "Staged files: ${#staged_files[@]} file(s)"
    for f in "${staged_files[@]}"; do
        printf " • %s\n" "$f"
    done

    local issues=0

    # 1. Filename-based checks
    for file in "${staged_files[@]}"; do
        for pattern in "${SCAN_PATTERNS[@]}"; do
        # shellcheck disable=SC2254
            case "$file" in
                $pattern)
                    log_warning "Sensitive file staged: $file (matched pattern: $pattern)"
                        issues=$((issues + 1))
            esac
        done
    done

    # 2. Content-based check (Python analyzer)
    if command -v python3 >/dev/null 2>&1 && [[ -f "$PY_ANALYZER" ]]; then
            local py_output
            py_output=$( git diff --cached | python3 "$PY_ANALYZER" || true)
            if [[ -n "$py_output" ]]; then
                echo "$py_output"
                log_error "Sensitive content detected in staged changes"

                local py_issues
                py_issues=$(echo "$py_output" | grep -c '^- File:' )
                issues=$(( issues + py_issues ))
            fi 
        else 
            log_warning "Python analyzer not found at: $PY_ANALYZER"
        fi 

        if [[ $issues -gt 0 ]]; then
            log_error "Detected $issues security issue(s) in staged files"
            return 1
        fi

        log_success "All staged files passed security validation"
            return 0
}


# Phase 4: SECURE COMMIT - Final Execution 

perform_secure_commit() {
    local commit_message="$1"
    log_step "PHASE 4: SECURE COMMIT - Finalizing"
    separator
    log_info "Security checks passed. Ready to commit..."
    echo ""
    echo " Commit details:"
    echo " Author: $(git config user.name) <$(git config user.email)>"
    echo " Branch: $(git branch --show-current)" 
    local staged_count
    staged_count=$(git diff --cached --name-only | wc -l | tr -d ' ')
    echo "  Files: ${staged_count} staged"
    echo "  Message: \"$commit_message\""
    echo " "

    if git commit -m "$commit_message"; then
        log_success "Commit successful!"
        echo ""
        echo "Latest commit:"
        git log -1 --oneline || true
        echo ""
        log_success "SecureGitX workflow complete - All good!"
    else 
        log_error "Commit failed" 
        exit 1
    fi
}

# Hook Installation & Management

install_hook_file() {
    # create a standardized pre-commit script that calls this script in hook-mode
    local hook_path="$1"
    local script_path="$2"
    cat > "$hook_path" <<EOF
#!/usr/bin/env bash
# SecureGitX pre-commit hook (v${SCRIPT_VERSION})
# Auto-installed on $(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date)
# Managed by SecureGitX - safe to edit above this line 

# call SecureGitX in hook mode; preserve cwd 
"$script_path" --hook-mode
exit \$?
EOF
    chmod +x "$hook_path"
}

install_hook() {
    log_step "Installing SecureGitX pre-commit hook..."
    separator
    if [[ ! -d ".git" ]]; then
        log_error "Not a git repository"
        exit 1
    fi 

    local script_path
    script_path="$(_abs_path "$0")"
    local hook_path=".git/hooks/pre-commit"

    # If hook doesn't exist, create
    if [[ ! -f "$hook_path" ]]; then
        install_hook_file "$hook_path" "$script_path"
        log_success "Pre-commit hook installed"
    return 0
    fi 

    # If hook exists and already contains marker, do nothing 
    if grep -q "SecureGitX pre-commit hook" "$hook_path" 2>/dev/null; then
        log_info "SecureGitX hook already installed"
    return 0
    fi 

    # Backup existing hook
    local backup
    backup="${hook_path}.backup.$(date +%s)"
    cp "$hook_path" "$backup"
    log_success "Existing hook backed up to $backup"
    install_hook_file "$hook_path" "$script_path"
    log_success "Installed SecureGitX pre-commit hook"
}

uninstall_hook() {
    log_step "Uninstalling SecureGitX pre-commit hook..."
    separator
    local hook_path=".git/hooks/pre-commit"
    if [[ ! -f "$hook_path" ]]; then
        log_info "No pre-commit hook installed"
    return 0
    fi

    if grep -q "SecureGitX pre-commit hook" "$hook_path" 2>/dev/null; then
        # try to find backup file (closest backup)
        local backup
        backup=$(find .git/hooks/pre-commit.backup* .git/hooks/pre-commit.backup.* 2>/dev/null | head -1 || true)
      if [[ -n "$backup" ]]; then
          mv "$backup" "$hook_path"
          log_success "Restored previous hook from backup: $backup"
      else
           # no backup: remove hook
        if confirm "No backup found. Remove SecureGitX hook anyway? [y/N]: "; then
          rm -f "$hook_path"
          log_success "SecureGitX hook removed"
        else
          log_info "Uninstall cancelled"
        fi
      fi
    else

        # Hook exists but not our marker
        log_warning "Pre-commit hook exists but was not installed by SecureGitX"
        if confirm "Remove/replace it anyway? [y/N]: "; then
            local backup2
            backup2="${hook_path}.manual_backup.$(date +%s)"
            mv "$hook_path" "$backup2"
            log_success "Existing hook moved to $backup2 and removed"
        else
        log_info "Uninstall skipped"
    fi
    fi
}


## Main Workflow 
show_banner() {

    if support_unicode && test -t 1; then
        # Unicode version with colors

    printf "%b \n" "${CYAN}"
    cat << "EOF"
    
 ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██╗████████╗██╗  ██╗
 ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔════╝ ██║╚══██╔══╝╚██╗██╔╝
 ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ██║  ███╗██║   ██║    ╚███╔╝ 
 ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ██║   ██║██║   ██║    ██╔██╗ 
 ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗╚██████╔╝██║   ██║   ██╔╝ ██╗
 ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝
                                        
EOF

echo "  ╭─────────────────────────────────────────╮"
printf "  │ %b │\n" "${CYAN}SecureGitX${NC} ${YELLOW}v${SCRIPT_VERSION}${NC}                      "
printf "  │ %b │\n" "${CYAN}Auth${NC} → ${CYAN}Scan${NC} → ${CYAN}Secure Commit${NC}            "
echo "  ╰─────────────────────────────────────────╯"


    else 
        # ASCII fallback version 
            cat << "EOF"
    
  ____                         _______     __      _   _
 / __|\______ _______ ____ ___|   ____( ) |  |__  \ \_/ /
 \___ \ / _ \/ __| | | | '__/ _ \|  _ _ | |  _ _\  \/+\/
  ___) |  __/ (__  |_| | | |  __/|__| | | |  |___  / /\ \
 |____/ \___|\___|\__,_|_|  \___|_____|_|_|______|/_/  \_\
                                        
EOF
    echo "  Git Security and Safety Automation v${SCRIPT_VERSION}"
    echo " Workflow: Auth => Scan => Validate => Secure Commit"
    separator
    fi

}

# ---------- Argument parsing ----------
_usage() {
  cat <<EOF
Usage: $0 [OPTIONS] [commit-message]

Options:
  --safe-email         Prompt/force switching to safe GitHub no-reply email
  --install            Install pre-commit hook
  --uninstall          Uninstall pre-commit hook
  --hook-mode          Run in hook-mode (used by installed hook)
  --help, -h           Show this help message
    Examples:
$0 # Setup and scan only
$0 "commit message" # Full workflow with commit
$0 --install # Install pre-commit hook
EOF
}


main() {
    local commit_message=""
    local force_safe_email=false
    local hook_mode=false

    # parse flags 
    while [[ $# -gt 0 ]]; do 
        case $1 in 
            --safe-email) force_safe_email=true shift ;;
            --install) install_hook; exit 0 ;;
            --uninstall) uninstall_hook; exit 0 ;;
            --hook-mode) hook_mode=true; shift ;;
            --help|-h) _usage; exit 0 ;;
            --) shift; break ;;
            -*)
                log_error "Unknown option: $1"
                _usage
                exit 1
                ;;
            *)
              # first non-flag argument is commit message; preserve spaces if quoted
              if [[ -z "$commit_message" ]] ; then
                commit_message="$1"
              else
                commit_message="$commit_message $1"
              fi 
              shift 
              ;; 
        esac
    done
    # Hook mode: minimal output, only scan staged files
    if [[ "$hook_mode" == "true" ]]; then
        ENFORCE_SAFE_EMAIL=false
        parse_config 2>/dev/null || true

        scan_staged_files
        scan_rc=$?

        case "$scan_rc" in
            0|2) exit 0 ;;
            *) exit 1 ;;
        esac
    fi  
    show_banner

    # Repo & config
    check_git_repo

    if ! parse_config; then
        log_info "No config found: creating default config ($CONFIG_FILE)"
        create_default_config
        # Re-parse to load values set by default
        parse_config || true
    else
        log_success "Configuration loaded ($CONFIG_FILE)"
    fi

    separator

    # Auth checks
    check_user_identity
    local current_email
    current_email=$(git config user.email)
    check_email_safety "$current_email" "$force_safe_email"
    check_branch_state

    separator

    # Scanning & gitignore
    ensure_gitignore
    separator
    if ! scan_sensitive_files; then
        log_error "Security scan found tracked sensitive files. Aborting commit flow."
        echo ""
        echo "Options:"
        echo " 1. Add files to .gitignore"
        echo "  2. Remove sensitive data from files"
        echo "  3. Clean history (git-filter-repo / BFG)"
        exit 1
    fi

  separator

  # Validation & commit
  if [[ -n "$commit_message" ]]; then
    scan_staged_files
    scan_rc=$?

    case "$scan_rc" in
        0) 
            separator
            perform_secure_commit "$commit_message"
            ;;
        2) 
            log_info "Nothing to commit"
            exit 0
            ;;
        *)
            log_error "Security issues found in staged files"
            echo ""
            echo "Fix staged issues (unstage, remove, or add to .gitignore) and retry."
            exit 1
        ;;
    esac
  else
    log_success "Security checks complete - repository is clean"
    echo ""
    echo "Next steps:"
    echo "  1. Stage your changes: git add <files>"
    echo "  2. Commit securely:    $0 \"your commit message\""
    log_info "No commit performed (no message provided)"
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi