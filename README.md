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

## Two Modes, One Tool

SecureGitX adapts to your workflow: 


### Mode 1: Manual (Explicit Control)

```bash
# You control when to run security checks 
git add src/
./securegitx.sh "feat: add feature"
```

**Best for:**
- Learning SecureGitx
- One-off commits 
- When you want explicit control

---

### Mode 2: AUtomatic (Set & Forget)
```bash
# One-time setup
./securegitx.sh --install

# Now just use normal git 
git add src/
git commit -m "feat: add feature"  # SecureGitX runs automatically!
```

**Best for:**
- Daily Development 
- Team projects
- When you might forget


| Scenario | Recommended Mode | Why |
|----------|-----------------|-----|
| **Trying SecureGitX** | Manual | No commitment needed |
| **Personal projects** | Your choice | Both work great |
| **Team projects** | Automatic | Everyone stays protected |
| **CI/CD pipelines** | Manual | More control |

**Pro tip:** Start with Manual, switch to Automatic when you're comfortable!

## Switching Modes
```bash
# Enable automatic mode 
./securegitx.sh --uninstall

# Disable automatic mode 
./securegitx.sh --uninstall

# Manual mode always works (even with hook installed)
./securegitx.sh "urgent commit"

```
---