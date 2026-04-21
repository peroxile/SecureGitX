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
import sys
from pathlib import Path

from securegitx import __version__

EXIT_CLEAN = 0
EXIT_BLOCKED = 1
EXIT_USAGE = 2
EXIT_GIT = 3
EXIT_RULES = 4


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securegitx",
        description="Lightweight pre-commit secret scanner",
    )
    parser.add_argument("--version", action="version", version=f"securegitx {__version__}")
    parser.add_argument("--config", metavar="FILE", help="Path to .securegitx.toml")

    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan for secrets")
    scan_mode = scan.add_mutually_exclusive_group()
    scan_mode.add_argument("--staged",  action="store_true", help="Scan staged changes (default)")
    scan_mode.add_argument("--tracked", action="store_true", help="Scan all tracked files")
    scan.add_argument("--format", choices=["text", "json"], default=None)
    scan.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], default=None,
                      dest="fail_on")
    scan.add_argument("--quiet", action="store_true")

    hook = sub.add_parser("hook", help="Manage pre-commit hook")
    hook_sub = hook.add_subparsers(dest="hook_command")
    hook_install = hook_sub.add_parser("install")
    hook_install.add_argument("--dry-run", action="store_true", dest="dry_run")
    hook_install.add_argument("--force",   action="store_true")
    hook_uninstall = hook_sub.add_parser("uninstall")
    hook_uninstall.add_argument("--dry-run", action="store_true", dest="dry_run")
    hook_sub.add_parser("status")

    init = sub.add_parser("init", help="Create default config")
    init.add_argument("--no-gitignore", action="store_true", dest="no_gitignore")

    rules = sub.add_parser("rules", help="Rule management")
    rules_sub = rules.add_subparsers(dest="rules_command")
    rules_sub.add_parser("validate")
    rules_sub.add_parser("list")

    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    from securegitx import gitops, scanner, report
    from securegitx.config import load_config, ConfigError
    from securegitx.rules import load_rules, load_allowlist, RuleLoadError

    config_path = Path(args.config) if args.config else None
    try:
        config = load_config(explicit_path=config_path)
    except ConfigError as e:
        print(f"[error] Config: {e}", file=sys.stderr)
        return EXIT_USAGE

    fmt = args.format or config.format
    fail_on = args.fail_on or config.fail_on
    quiet = args.quiet

    try:
        rules = load_rules()
        allowlist = load_allowlist()
    except RuleLoadError as e:
        print(f"[error] Rules: {e}", file=sys.stderr)
        return EXIT_RULES

    try:
        if not gitops.is_git_repo():
            print("[error] Not a git repository", file=sys.stderr)
            return EXIT_GIT

        findings: list = []

        if args.tracked:
            for filename in gitops.tracked_files():
                findings.extend(scanner.scan_filenames([filename], rules, allowlist))
                try:
                    content = gitops.read_tracked_file(filename)
                    findings.extend(
                        scanner.scan_file_content(
                            content, filename, rules, allowlist, config.entropy_threshold
                        )
                    )
                except gitops.GitError:
                    pass
        else:
            staged = gitops.staged_files()
            if not staged:
                if not quiet:
                    print("  Nothing staged — no files to scan")
                return EXIT_CLEAN
            findings.extend(scanner.scan_filenames(staged, rules, allowlist))
            diff = gitops.staged_diff()
            findings.extend(
                scanner.scan_diff(diff, rules, allowlist, config.entropy_threshold)
            )

    except gitops.GitError as e:
        print(f"[error] Git: {e}", file=sys.stderr)
        return EXIT_GIT

    if not quiet:
        if fmt == "json":
            report.format_json(findings)
        else:
            report.format_text(findings)

    return EXIT_BLOCKED if report.exceeds_threshold(findings, fail_on) else EXIT_CLEAN


def _cmd_hook(args: argparse.Namespace) -> int:
    from securegitx import gitops, hooks

    try:
        root = gitops.repo_root()
    except gitops.GitError as e:
        print(f"[error] {e}", file=sys.stderr)
        return EXIT_GIT

    cmd = getattr(args, "hook_command", None)
    if cmd == "install":
        try:
            print(hooks.install(root, force=args.force, dry_run=args.dry_run))
        except hooks.HookError as e:
            print(f"[error] {e}", file=sys.stderr)
            return EXIT_USAGE
    elif cmd == "uninstall":
        try:
            print(hooks.uninstall(root, dry_run=args.dry_run))
        except hooks.HookError as e:
            print(f"[error] {e}", file=sys.stderr)
            return EXIT_USAGE
    elif cmd == "status":
        print(hooks.status(root))
    else:
        print("[error] Specify: hook install | hook uninstall | hook status", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_CLEAN


def _cmd_init(args: argparse.Namespace) -> int:
    config_file = Path(".securegitx.toml")
    if config_file.exists():
        print(f"Config already exists: {config_file}")
        return EXIT_CLEAN
    config_file.write_text(
        'enforce_safe_email = true\n'
        'auto_gitignore = true\n'
        'entropy_threshold = 4.5\n'
        'fail_on = "high"\n'
        'format = "text"\n'
    )
    print(f"Created {config_file}")
    if not args.no_gitignore:
        gitignore = Path(".gitignore")
        entry = "\n# SecureGitX\n.securegitx.toml\n"
        if gitignore.exists():
            if ".securegitx.toml" not in gitignore.read_text():
                gitignore.open("a").write(entry)
                print("Added .securegitx.toml to .gitignore")
        else:
            gitignore.write_text(entry.lstrip())
            print("Created .gitignore")
    return EXIT_CLEAN


def _cmd_rules(args: argparse.Namespace) -> int:
    from securegitx.rules import load_rules, RuleLoadError
    cmd = getattr(args, "rules_command", None)
    try:
        rules = load_rules()
    except RuleLoadError as e:
        print(f"[error] {e}", file=sys.stderr)
        return EXIT_RULES
    if cmd == "validate":
        print(f"  {len(rules)} rules loaded and valid")
    elif cmd == "list":
        fmt = "{:<10} {:<12} {:<10} {}"
        print(fmt.format("ID", "SEVERITY", "TYPE", "NAME"))
        print("─" * 60)
        for r in rules:
            print(fmt.format(r.id, r.severity, r.type, r.name))
    else:
        print("[error] Specify: rules validate | rules list", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_CLEAN


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        sys.exit(EXIT_USAGE)
    handlers = {"scan": _cmd_scan, "hook": _cmd_hook, "init": _cmd_init, "rules": _cmd_rules}
    sys.exit(handlers[args.command](args))


if __name__ == "__main__":
    main()