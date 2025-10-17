# SecureGitX

> **Automate Git security & Email safety for modern developers**

SecureGitx prevents you from commiting secrets, helps protect your repo email and manages `.gitignore` files all with a single command. No complex setup, no dependencies, just run it. 

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/bash-5.0%2B-green.svg)](https://www.gnu.org/software/bash/)


![Diagram](assets/diagram.png)


## Why SecureGitX?

**The Problem:**
- Developers accidentally commit API keys, passwords, and tokens
- Personal emails leak into public repos
- Forgetting `.gitignore` files exposes sensitive data
- Existing tools are slow, complex, or outdated

**The Solution:**
SecureGitX prevents you from committing secrets, helps protect your repository email, and manages .gitignore files—all with a single command. No complex setup, no dependencies; just run it.

---


## Features 

| Feature | Description |
|---------|-------------|
|  **Secret Detection** | Scans for 20+ patterns including API keys, credentials, private keys, and tokens |
|  **Noreply Recommendation** | Recommends using GitHub's no-reply email |
|  **Smart .gitignore** | Creates a comprehensive `.gitignore` file based on project type |
|  **Fast** | Pure Bash — no dependencies, runs in milliseconds |
|  **Educational** | Explains *why* something is dangerous |
|  **Zero Config** | Works out-of-the-box with optional customization |

---

## Quick start 

### Installation 


``` bash
# Download the script
curl -L https://raw.githubusercontent.com/peroxile/SecureGitX/main/securegitx.sh -o securegitx.sh



# Make it executable 
chmod +x securegitx.sh

# Optional: Move to your PATH
sudo mv securegitx.sh /usr/local/bin/securegitx
```

### Usage 

```bash
# Run security checks in your repo
./securegitx.sh

# Commit with security validation

./securegitx.sh "feat: add authentication"
```

---
