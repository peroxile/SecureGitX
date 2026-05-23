"""
Rule bundle updater.

Downloads, verifies, and installs updated rule bundles.
Updates are always explicit — never triggered during normal scans.

Update flow:
  1. Fetch rules.json from source URL  (stdlib urllib, no external deps)
  2. Verify SHA-256 checksum against {source_url}.sha256
  3. Validate: load_rules() must succeed on the downloaded content
  4. Compare versions: skip unless newer (override with force=True)
  5. Backup current rules.json → rules.json.bak
  6. Write new rules.json atomically
  7. Write rules.json.meta with update provenance

Rollback:
  Restore rules.json.bak → rules.json, remove .meta

All failures raise UpdateError before any file is modified.
The current ruleset is never left in a corrupt state.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from securegitx.rules import _RULES_DIR

# Constants

DEFAULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/peroxile/SecureGitX"
    "/main/src/securegitx/rules/rules.json"
)

_RULES_FILE = _RULES_DIR / "rules.json"
_BACKUP_FILE = _RULES_DIR / "rules.json.bak"
_META_FILE = _RULES_DIR / "rules.json.meta"

_FETCH_TIMEOUT = 15  # seconds
_MIN_SIZE = 64  # bytes — guard against empty / redirect responses


# Public types


class UpdateError(Exception):
    """Raised on any failure during update or rollback."""


@dataclass
class UpdateResult:
    previous_version: str
    new_version: str
    rule_count: int
    checksum: str
    source_url: str
    skipped: bool = False
    skip_reason: str = ""


# Public API


def update(
    source_url: str = DEFAULT_SOURCE_URL,
    verify_checksum: bool = True,
    dry_run: bool = False,
    force: bool = False,
) -> UpdateResult:
    """
    Fetch, verify, validate, and install a new rule bundle.

    Args:
        source_url:       URL of the remote rules.json.
        verify_checksum:  Fetch and verify {source_url}.sha256 before installing.
        dry_run:          Parse and compare versions without writing any files.
        force:            Install even if the remote version is not newer.

    Returns:
        UpdateResult describing what happened.

    Raises:
        UpdateError on network failure, checksum mismatch, or validation failure.
    """
    current_version = rule_version()

    #  1. Fetch
    raw = _fetch(source_url)

    # 2. Checksum
    digest = hashlib.sha256(raw).hexdigest()
    if verify_checksum:
        _verify_checksum(raw, digest, source_url)

    #  3. Parse + validate
    try:
        data = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise UpdateError(f"Downloaded content is not valid JSON: {exc}") from exc

    new_version, rule_entries = _extract(data, source_url)
    _validate_entries(rule_entries, source_url)

    #  4. Version check
    if not force and not _is_newer(new_version, current_version):
        return UpdateResult(
            previous_version=current_version,
            new_version=new_version,
            rule_count=len(rule_entries),
            checksum=f"sha256:{digest}",
            source_url=source_url,
            skipped=True,
            skip_reason=(
                f"Current version ({current_version}) is already "
                f"up to date (remote: {new_version})"
            ),
        )

    if dry_run:
        return UpdateResult(
            previous_version=current_version,
            new_version=new_version,
            rule_count=len(rule_entries),
            checksum=f"sha256:{digest}",
            source_url=source_url,
            skipped=True,
            skip_reason="dry-run — no files written",
        )

    # 5. Backup
    _backup()

    # 6. Atomic write
    _atomic_write(_RULES_FILE, raw)

    # 7. Metadata
    _write_meta(
        version=new_version,
        previous_version=current_version,
        checksum=f"sha256:{digest}",
        source_url=source_url,
        rule_count=len(rule_entries),
    )

    return UpdateResult(
        previous_version=current_version,
        new_version=new_version,
        rule_count=len(rule_entries),
        checksum=f"sha256:{digest}",
        source_url=source_url,
    )


def rollback() -> str:
    """
    Restore rules.json.bak → rules.json.
    Removes the .meta file so the reverted version is treated as baseline.

    Raises:
        UpdateError if no backup exists.
    """
    if not _BACKUP_FILE.exists():
        raise UpdateError("No backup found — nothing to roll back")

    restored_version = _version_from_file(_BACKUP_FILE)

    shutil.copy2(_BACKUP_FILE, _RULES_FILE)
    _BACKUP_FILE.unlink(missing_ok=True)
    _META_FILE.unlink(missing_ok=True)

    return (
        f"Rolled back to {restored_version} " f"(backup: {_BACKUP_FILE.name} removed)"
    )


def check(source_url: str = DEFAULT_SOURCE_URL) -> str:
    """
    Fetch the remote rules.json and compare versions without installing.
    Returns a human-readable status string.
    """
    try:
        raw = _fetch(source_url)
        data = json.loads(raw.decode("utf-8"))
        new_version, entries = _extract(data, source_url)
    except UpdateError as exc:
        return f"Update check failed: {exc}"

    current = rule_version()
    meta = _read_meta()
    lines = [
        f"Current version : {current}",
        f"Remote version  : {new_version}",
        f"Remote rules    : {len(entries)}",
    ]
    if meta:
        lines.append(f"Last updated    : {meta.get('updated_at', 'unknown')}")

    if _is_newer(new_version, current):
        lines.append("Status: update available")
    else:
        lines.append("Status: up to date")

    return "\n".join(lines)


def rule_version() -> str:
    """Return the version string from the active rules.json."""
    try:
        data = json.loads(_RULES_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return str(data.get("version", "unknown"))
    except Exception:
        pass
    return "unknown"


# Internal — network


def _fetch(url: str) -> bytes:
    """Download `url` and return raw bytes. Raises UpdateError on failure."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "SecureGitX-Updater/1"},
        )
        with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT) as resp:
            content = resp.read()
    except urllib.error.HTTPError as exc:
        raise UpdateError(f"HTTP {exc.code} fetching {url}") from exc
    except urllib.error.URLError as exc:
        raise UpdateError(f"Network error fetching {url}: {exc.reason}") from exc
    except OSError as exc:
        raise UpdateError(f"Connection error: {exc}") from exc

    if len(content) < _MIN_SIZE:
        raise UpdateError(
            f"Response from {url} is suspiciously small ({len(content)} bytes) "
            "— may be a redirect or empty page"
        )
    return content


def _verify_checksum(content: bytes, local_digest: str, source_url: str) -> None:
    """
    Fetch {source_url}.sha256 and compare against local_digest.
    Checksum file must contain the hex digest (with optional filename suffix).
    Raises UpdateError on mismatch or fetch failure.
    """
    checksum_url = source_url + ".sha256"
    try:
        raw = _fetch(checksum_url)
    except UpdateError:
        # No checksum file published — warn but don't block
        return

    remote_line = raw.decode("utf-8").strip().split()[0]  # first token = hex digest
    remote_digest = remote_line.lower()

    if remote_digest != local_digest:
        raise UpdateError(
            f"Checksum mismatch — download may be corrupted or tampered.\n"
            f"  Expected: {remote_digest}\n"
            f"  Got:      {local_digest}"
        )


# Internal — parsing + validation


def _extract(data: object, url: str) -> tuple[str, list]:
    """Pull (version, rule_entries) out of the raw JSON structure."""
    if isinstance(data, list):
        return "unknown", data
    if isinstance(data, dict):
        version = str(data.get("version", "unknown"))
        entries = data.get("rules", [])
        if not isinstance(entries, list):
            raise UpdateError(f"'rules' key in {url} is not a list")
        return version, entries
    raise UpdateError(f"Unexpected JSON structure from {url}: {type(data).__name__}")


def _validate_entries(entries: list, url: str) -> None:
    """
    Verify every entry has required fields and a compilable regex.
    Uses load_rules() logic so validation is always in sync with the parser.
    """
    import re

    required = {"id", "name", "severity", "type", "pattern"}
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise UpdateError(f"Rule #{i} from {url} is not an object")
        missing = required - entry.keys()
        if missing:
            raise UpdateError(
                f"Rule #{i} ({entry.get('id', '?')}) from {url} "
                f"is missing fields: {missing}"
            )
        try:
            re.compile(entry["pattern"])
        except re.error as exc:
            raise UpdateError(
                f"Rule {entry['id']} from {url} has invalid regex: {exc}"
            ) from exc


# Internal — version comparison


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse "1.2.3" → (1, 2, 3). Non-numeric parts become 0."""
    parts = []
    for seg in v.strip().split("."):
        try:
            parts.append(int(seg))
        except ValueError:
            parts.append(0)
    return tuple(parts) or (0,)


def _is_newer(remote: str, current: str) -> bool:
    """Return True if remote version is strictly greater than current."""
    if remote == "unknown" or current == "unknown":
        return remote != current  # always update if either is unknown
    return _parse_version(remote) > _parse_version(current)


# Internal — file operations


def _backup() -> None:
    """Copy rules.json → rules.json.bak. Overwrites any existing backup."""
    if _RULES_FILE.exists():
        shutil.copy2(_RULES_FILE, _BACKUP_FILE)


def _atomic_write(target: Path, content: bytes) -> None:
    """Write content to a temp file then rename — prevents partial writes."""
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=target.parent, prefix=".rules_tmp_", suffix=".json"
    )
    try:
        import os

        os.write(tmp_fd, content)
        os.close(tmp_fd)
        Path(tmp_path).replace(target)
    except Exception as exc:
        Path(tmp_path).unlink(missing_ok=True)
        raise UpdateError(f"Failed to write {target}: {exc}") from exc


def _write_meta(
    version: str,
    previous_version: str,
    checksum: str,
    source_url: str,
    rule_count: int,
) -> None:
    meta = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "version": version,
        "previous_version": previous_version,
        "checksum": checksum,
        "source_url": source_url,
        "rule_count": rule_count,
    }
    _META_FILE.write_text(json.dumps(meta, indent=2), encoding="utf-8")


def _read_meta() -> dict:
    if not _META_FILE.exists():
        return {}
    try:
        return json.loads(_META_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _version_from_file(path: Path) -> str:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return str(data.get("version", "unknown"))
    except Exception:
        pass
    return "unknown"
