"""
CLI entry point.

Exit codes:
  0  clean / success
  1  findings above threshold
  2  usage / config error
  3  git / repo error
  4  rule validation error
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from securegitx import __version__
from securegitx import terminal as T

EXIT_CLEAN = 0
EXIT_BLOCKED = 1
EXIT_USAGE = 2
EXIT_GIT = 3
EXIT_RULES = 4

_SUBCOMMANDS = {"scan", "hook", "init", "rules", "daemon"}


# Internal git helpers


def _git_cfg(key: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "config", key], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except subprocess.CalledProcessError:
        return ""


def _git_branch() -> str:
    try:
        branch = subprocess.check_output(
            ["git", "branch", "--show-current"], text=True, stderr=subprocess.DEVNULL
        ).strip()
        return branch or "detached HEAD"
    except subprocess.CalledProcessError:
        return "unknown"


# Auth phase (informational; non-fatal for scan)


def _show_auth_phase() -> None:
    T.log_step("PHASE 1: AUTHENTICATION — Verifying Identity")
    T.separator()

    name = _git_cfg("user.name")
    email = _git_cfg("user.email")

    if not name:
        T.log_error('user.name not set — fix with: git config user.name "Your Name"')
    if not email:
        T.log_error(
            'user.email not set — fix with: git config user.email "you@example.com"'
        )
    if name and email:
        T.log_success(f"Identity verified: {name} <{email}>")

    if email.endswith("@users.noreply.github.com"):
        T.log_success("Email protected (GitHub no-reply)")
    elif email:
        T.log_info(f"Email: {email}")
        T.log_info(
            "Tip: use a no-reply email — GitHub Settings → Emails → Keep my email private"
        )

    branch = _git_branch()
    if branch == "detached HEAD":
        T.log_warning("Detached HEAD — check out a branch before committing")
    else:
        T.log_success(f"On branch {branch}")


# Argument parser


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="securegitx")
    parser.add_argument(
        "--version", action="version", version=f"securegitx {__version__}"
    )
    parser.add_argument("--config", metavar="FILE", help="Path to .securegitx.toml")

    sub = parser.add_subparsers(dest="command")

    # scan
    scan = sub.add_parser("scan", help="Scan for secrets")
    mode = scan.add_mutually_exclusive_group()
    mode.add_argument(
        "--staged", action="store_true", help="Scan staged changes (default)"
    )
    mode.add_argument("--tracked", action="store_true", help="Scan all tracked files")
    scan.add_argument("--format", choices=["text", "json"], default=None)
    scan.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default=None,
        dest="fail_on",
    )
    scan.add_argument("--quiet", action="store_true")

    # hook
    hook = sub.add_parser("hook", help="Manage pre-commit hook")
    hook_sub = hook.add_subparsers(dest="hook_command")
    hi = hook_sub.add_parser("install")
    hi.add_argument("--dry-run", action="store_true", dest="dry_run")
    hi.add_argument("--force", action="store_true")
    hu = hook_sub.add_parser("uninstall")
    hu.add_argument("--dry-run", action="store_true", dest="dry_run")
    hook_sub.add_parser("status")

    # init
    init = sub.add_parser("init", help="Create default config")
    init.add_argument("--no-gitignore", action="store_true", dest="no_gitignore")

    # rules
    rules = sub.add_parser("rules", help="Rule management")
    rules_sub = rules.add_subparsers(dest="rules_command")
    rules_sub.add_parser("validate")
    rules_sub.add_parser("list")

    # daemon
    daemon = sub.add_parser("daemon", help="Background file watcher")
    daemon_sub = daemon.add_subparsers(dest="daemon_command")
    ds = daemon_sub.add_parser("start")
    ds.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Poll interval in seconds (default: 2.0)",
    )
    daemon_sub.add_parser("stop")
    daemon_sub.add_parser("status")

    return parser


# Command handlers


def _cmd_scan(args: argparse.Namespace) -> int:
    from securegitx import gitops, scanner, report
    from securegitx.config import load_config, ConfigError
    from securegitx.rules import load_rules, load_allowlist, RuleLoadError

    config_path = Path(args.config) if args.config else None
    try:
        config = load_config(explicit_path=config_path)
    except ConfigError as e:
        T.log_error(f"Config: {e}")
        return EXIT_USAGE

    fmt = args.format or config.format
    fail_on = args.fail_on or config.fail_on
    quiet = args.quiet
    verbose = fmt != "json" and not quiet

    try:
        rules = load_rules()
        allowlist = load_allowlist()
    except RuleLoadError as e:
        T.log_error(f"Rules: {e}")
        return EXIT_RULES

    try:
        if not gitops.is_git_repo():
            T.log_error("Not a git repository")
            return EXIT_GIT

        if verbose:
            _show_auth_phase()
            T.separator()
            print()
            label = "Tracked Files" if args.tracked else "Staged Changes"
            T.log_step(f"PHASE 2: SCANNING — {label}")
            T.separator()

        findings: list = []

        if args.tracked:
            files = list(gitops.tracked_files())
            if verbose:
                T.log_info(f"Scanning {len(files)} tracked file(s)...")
            for filename in files:
                findings.extend(scanner.scan_filenames([filename], rules, allowlist))
                try:
                    content = gitops.read_tracked_file(filename)
                    if content is None:
                        continue
                    findings.extend(
                        scanner.scan_file_content(
                            content,
                            filename,
                            rules,
                            allowlist,
                            config.entropy_threshold,
                        )
                    )
                except gitops.GitError:
                    pass
        else:
            staged = gitops.staged_files()
            if not staged:
                if verbose:
                    T.log_warning("No files staged — nothing to scan")
                elif not quiet:
                    print("  Nothing staged — no files to scan")
                return EXIT_CLEAN
            if verbose:
                T.log_info(f"{len(staged)} file(s) staged")
                for f in staged:
                    print(f"    • {f}")
            findings.extend(scanner.scan_filenames(staged, rules, allowlist))
            diff = gitops.staged_diff()
            findings.extend(
                scanner.scan_diff(diff, rules, allowlist, config.entropy_threshold)
            )

    except gitops.GitError as e:
        T.log_error(f"Git: {e}")
        return EXIT_GIT

    blocked = report.exceeds_threshold(findings, fail_on)

    if verbose:
        T.separator()
        print()
        if findings:
            T.log_warning(f"{len(findings)} finding(s) detected")
        else:
            T.log_success("No secrets detected")

    if not quiet:
        if fmt == "json":
            report.format_json(findings)
        elif findings:
            report.format_text(findings)

    if verbose:
        if blocked:
            print()
            T.log_error("Commit blocked — resolve findings above and retry")
            print()
            print("  Remediation:")
            print("    • Remove the secret and rotate it immediately")
            print("    • Add an allowlist entry in .securegitx.toml")
            print("    • Unstage with: git restore --staged <file>")
        else:
            print()
            T.log_success("All clear — repository is clean")

    return EXIT_BLOCKED if blocked else EXIT_CLEAN


def _cmd_commit(message: str) -> int:
    from securegitx import gitops, scanner, report
    from securegitx.config import load_config, ConfigError
    from securegitx.rules import load_rules, load_allowlist, RuleLoadError

    _show_auth_phase()
    T.separator()
    print()

    try:
        config = load_config()
    except ConfigError as e:
        T.log_error(f"Config: {e}")
        return EXIT_USAGE

    try:
        rules = load_rules()
        allowlist = load_allowlist()
    except RuleLoadError as e:
        T.log_error(f"Rules: {e}")
        return EXIT_RULES

    try:
        if not gitops.is_git_repo():
            T.log_error("Not a git repository")
            return EXIT_GIT

        staged = gitops.staged_files()

        T.log_step("PHASE 2: SCANNING — Staged Changes")
        T.separator()

        if not staged:
            T.log_warning("No files staged — nothing to commit")
            return EXIT_CLEAN

        T.log_info(f"{len(staged)} file(s) staged")
        for f in staged:
            print(f"    • {f}")

        findings: list = []
        findings.extend(scanner.scan_filenames(staged, rules, allowlist))
        diff = gitops.staged_diff()
        findings.extend(
            scanner.scan_diff(diff, rules, allowlist, config.entropy_threshold)
        )

    except gitops.GitError as e:
        T.log_error(f"Git: {e}")
        return EXIT_GIT

    T.separator()
    print()

    if report.exceeds_threshold(findings, config.fail_on):
        report.format_text(findings)
        print()
        T.log_error("Commit blocked — resolve findings above and retry")
        return EXIT_BLOCKED

    if findings:
        report.format_text(findings)

    T.log_success("No secrets detected")
    T.separator()
    print()

    T.log_step("PHASE 3: SECURE COMMIT")
    T.separator()
    T.log_info(f"Author:  {_git_cfg('user.name')} <{_git_cfg('user.email')}>")
    T.log_info(f"Branch:  {_git_branch()}")
    T.log_info(f"Message: {message}")
    print()

    try:
        subprocess.run(["git", "commit", "-m", message], check=True)
        print()
        T.log_success("Commit successful")
        subprocess.run(["git", "log", "-1", "--oneline"])
    except subprocess.CalledProcessError:
        T.log_error("Commit failed")
        return EXIT_GIT

    return EXIT_CLEAN


def _cmd_hook(args: argparse.Namespace) -> int:
    from securegitx import gitops, hooks

    try:
        root = gitops.repo_root()
    except gitops.GitError as e:
        T.log_error(str(e))
        return EXIT_GIT

    cmd = getattr(args, "hook_command", None)

    if cmd == "install":
        T.log_step("Installing pre-commit hook...")
        T.separator()
        try:
            T.log_success(hooks.install(root, force=args.force, dry_run=args.dry_run))
        except hooks.HookError as e:
            T.log_error(str(e))
            return EXIT_USAGE

    elif cmd == "uninstall":
        T.log_step("Removing pre-commit hook...")
        T.separator()
        try:
            T.log_success(hooks.uninstall(root, dry_run=args.dry_run))
        except hooks.HookError as e:
            T.log_error(str(e))
            return EXIT_USAGE

    elif cmd == "status":
        T.log_info(hooks.status(root))

    else:
        T.log_error("Specify: hook install | hook uninstall | hook status")
        return EXIT_USAGE

    return EXIT_CLEAN


def _cmd_init(args: argparse.Namespace) -> int:
    T.log_step("Initializing SecureGitX...")
    T.separator()

    config_file = Path(".securegitx.toml")
    if config_file.exists():
        T.log_info(f"Config already exists: {config_file}")
        return EXIT_CLEAN

    config_file.write_text(
        "enforce_safe_email = true\n"
        "auto_gitignore = true\n"
        "entropy_threshold = 4.5\n"
        'fail_on = "high"\n'
        'format = "text"\n'
    )
    T.log_success(f"Created {config_file}")

    if not args.no_gitignore:
        gitignore = Path(".gitignore")
        entry = "\n# SecureGitX\n.securegitx.toml\n"
        if gitignore.exists():
            if ".securegitx.toml" not in gitignore.read_text():
                gitignore.open("a").write(entry)
                T.log_success("Added .securegitx.toml to .gitignore")
        else:
            gitignore.write_text(entry.lstrip())
            T.log_success("Created .gitignore")

    return EXIT_CLEAN


def _cmd_rules(args: argparse.Namespace) -> int:
    from securegitx.rules import load_rules, RuleLoadError

    cmd = getattr(args, "rules_command", None)
    try:
        rules = load_rules()
    except RuleLoadError as e:
        T.log_error(str(e))
        return EXIT_RULES

    if cmd == "validate":
        T.log_success(f"{len(rules)} rules loaded and valid")
    elif cmd == "list":
        print("{:<10} {:<12} {:<10} {}".format("ID", "SEVERITY", "TYPE", "NAME"))
        print("─" * 60)
        for r in rules:
            print("{:<10} {:<12} {:<10} {}".format(r.id, r.severity, r.type, r.name))
    else:
        T.log_error("Specify: rules validate | rules list")
        return EXIT_USAGE

    return EXIT_CLEAN


def _cmd_daemon(args: argparse.Namespace) -> int:
    from securegitx import gitops
    from securegitx import daemon as _daemon

    try:
        root = gitops.repo_root()
    except gitops.GitError as e:
        T.log_error(str(e))
        return EXIT_GIT

    cmd = getattr(args, "daemon_command", None)

    if cmd == "start":
        T.log_step("Starting SecureGitX daemon...")
        T.separator()
        try:
            T.log_success(_daemon.start(root, interval=getattr(args, "interval", 2.0)))
        except _daemon.DaemonError as e:
            T.log_error(str(e))
            return EXIT_USAGE

    elif cmd == "stop":
        T.log_step("Stopping SecureGitX daemon...")
        T.separator()
        try:
            T.log_success(_daemon.stop(root))
        except _daemon.DaemonError as e:
            T.log_error(str(e))
            return EXIT_USAGE

    elif cmd == "status":
        print(_daemon.status(root))

    else:
        T.log_error("Specify: daemon start | daemon stop | daemon status")
        return EXIT_USAGE

    return EXIT_CLEAN


# Entry point

def main(argv: list[str] | None = None) -> None:
    args_list = sys.argv[1:] if argv is None else list(argv)

    # Bare invocation with no args → show banner + help
    if not args_list:
        T.show_banner(__version__)
        _build_parser().print_help()
        sys.exit(EXIT_USAGE)

    # Bare commit message: securegitx "feat: add thing"
    if not args_list[0].startswith("-") and args_list[0] not in _SUBCOMMANDS:
        sys.exit(_cmd_commit(" ".join(args_list)))

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        T.show_banner(__version__)
        parser.print_help()
        sys.exit(EXIT_USAGE)

    handlers = {
        "scan": _cmd_scan,
        "hook": _cmd_hook,
        "init": _cmd_init,
        "rules": _cmd_rules,
        "daemon": _cmd_daemon,
    }
    sys.exit(handlers[args.command](args))


if __name__ == "__main__":
    main()
