#!/ bin/bash

set -e 

CONFIG_FILE = " "
SAFE_EMAIL = " "
SAFE_NAME = " " 
DEFAULT_BRANCH = ""
IGNORE_FILE = ""
LOG_FILE  = " "
LOG_TO_REPO = "false"


SENSITIVE_PATTERNS = ("*.env" "*pem" "*key" "secrets/" "key/" "config.json" "*.wallet" "*.seed" "*.keystore" "*.mnemonic" "private/" "*.db" "database" "*.sqlite" "node_modules/" "__pycache__/" "*.log" "*.contract" "securegitxconfig" "*.securegitx.log")


init_repo() {
    echo "[*]  Iniatilizing/Detecting workspace.."
    if [[! -d ".git"]]; then
        echo "[!] No Git repo found. Initializing..."
        git init
        echo "[✓] Git repo initialized."
    fi



    if ! git remote | grep - q origin; then
        echo "[!] No remote repo URL (e.g., git@github.com:username/repo.git):" REMOTE_URL
    if [[ -n "$REMOTE_URL"]]; then  
        git remote add origin "$REMOTE_URL"
        log_action "Added remote $REMOTE_URL"
    else
        echo "[x] No remote configured. Exiting."
        exit 1
    fi
        fi


}