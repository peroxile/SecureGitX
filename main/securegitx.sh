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


        if [[ ! -f "$CONFIG_FILE"]]; then   
            echo "[*] Creating config file: $CONFIG_FILE"
            read -p "Enter your Github username for no-reply email: " GH_USER
            if [[-n "${GH-USER}@.noreply.github.com"]]
            fi
            cat <<EOF > "$CONFIG_FILE


# Main configuration 

  SAFE_EMAIL = "$SAFE_EMAIL"
  SAFE_NAME = "$SAFE_NAME"
  DEFAULT_BRANCH = "$DEFAULT_BRANCH"
  LOG_TO_REPO= = "$LOG_TO_REPO"

EOF
    echo "[✓] Config created. Edit $CONFIG_FILE for customizations."
    log_action "Created config file"
    fi

create_gitignore
echo "[✓] Workspace initialized/detected."

}