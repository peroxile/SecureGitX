# SecureGitX
Mega version of Secure git written in Bash.

SecureGitX is a robust, Bash-based workflow automation script designed to enhance security,usability and collabration for developers, with focus on web3 and critical systems. it transforms standard Git operation into a secure, non-interactive, and features-rich experience, addressing common pitfalls like secret leaks and unattributed commits.


## Key Features

- Security-First Design; Scans for secrets (e.g API keys, .wallet, .keystore..) using custom patterns, blocks sensitive files, and support GPG signing. Sensitive ignores (e.g securegitx.log, .securegitxconfig) all kept locally preventing public exposure.

- Seamless Usability: Runs wih a simple `` securegitx.sh `` command(no flags), matching raw Git speed, with an optional menu (``--menu``) for advanced tasks.
