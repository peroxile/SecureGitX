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

