"""Terminal output primitives: icons, color, banner, separators."""

from __future__ import annotations

import os
import sys

_IS_TTY = sys.stdout.isatty()
_USE_UNICODE = _IS_TTY and (
    "UTF-8" in os.environ.get("LANG", "") or "UTF-8" in os.environ.get("LC_ALL", "")
)

if _USE_UNICODE:
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    CYAN = "\033[0;36m"
    NC = "\033[0m"
    OK, WARN, ERR, INFO, STEP = "✓", "⚠", "✗", "ℹ", "▶"
else:
    RED = GREEN = YELLOW = BLUE = CYAN = NC = ""
    OK, WARN, ERR, INFO, STEP = "[OK]", "[WARN]", "[ERR]", "[INFO]", ">"

SEP = "──────────────────────────────────"


def separator() -> None:
    print(SEP)


def log_success(msg: str) -> None:
    print(f" {GREEN}{OK}{NC} {msg}")


def log_info(msg: str) -> None:
    print(f" {BLUE}{INFO}{NC} {msg}")


def log_warning(msg: str) -> None:
    print(f" {YELLOW}{WARN}{NC} {msg}")


def log_error(msg: str) -> None:
    print(f" {RED}{ERR}{NC} {msg}", file=sys.stderr)


def log_step(msg: str) -> None:
    print(f" {CYAN}{STEP}{NC} {msg}")


_BANNER_ART = r"""
 ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██╗████████╗██╗  ██╗
 ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔════╝ ██║╚══██╔══╝╚██╗██╔╝
 ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ██║  ███╗██║   ██║    ╚███╔╝ 
 ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ██║   ██║██║   ██║    ██╔██╗ 
 ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗╚██████╔╝██║   ██║   ██╔╝ ██╗
 ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝
"""

# Inner box width (visual chars between the │ borders)
_BOX_W = 41


def show_banner(version: str) -> None:
    """Print banner. No-op when stdout is not a TTY."""
    if not _IS_TTY:
        return
    v = version.lstrip("v")
    if _USE_UNICODE:
        print(f"{CYAN}{_BANNER_ART}{NC}")
        # Plain-text versions for width calculation (ANSI codes are zero-width)
        l1_plain = f" SecureGitX v{v}"
        l2_plain = " Auth → Scan → Secure Commit"
        l1_color = f" {CYAN}SecureGitX{NC} {YELLOW}v{v}{NC}"
        l2_color = f" {CYAN}Auth{NC} → {CYAN}Scan{NC} → {CYAN}Secure Commit{NC}"
        print(f"  ╭{'─' * _BOX_W}╮")
        print(f"  │{l1_color}{' ' * (_BOX_W - len(l1_plain))}│")
        print(f"  │{l2_color}{' ' * (_BOX_W - len(l2_plain))}│")
        print(f"  ╰{'─' * _BOX_W}╯")
    else:
        print(f"\n  SecureGitX v{v} — Auth => Scan => Secure Commit")
        print("  " + "=" * _BOX_W)
    print()
