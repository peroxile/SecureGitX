from __future__ import annotations

from pathlib import Path

from securegitx import gitignore_build as g


def test_build_section_includes_markers_and_always_entries():
    section = g.build_section("python")

    assert g.SECTION_START in section
    assert g.SECTION_END in section
    assert ".securegitx/" in section
    assert ".securegitx.toml" in section
    assert "*.env" in section
    assert "id_rsa" in section
    assert "# Python" in section
    assert "__pycache__/" in section
    assert "node_modules/" not in section


def test_build_section_includes_extra_entries():
    section = g.build_section(
        "generic", extra_entries=["secrets/api.key", "tmp/generated.env"]
    )

    assert "Detected by SecureGitX daemon" in section
    assert "secrets/api.key" in section
    assert "tmp/generated.env" in section


def test_build_section_falls_back_to_generic():
    section = g.build_section("unknown-project-type")

    assert "# Build output" in section
    assert "dist/" in section
    assert "build/" in section
    assert "node_modules/" in section
    assert "# Python" not in section


def test_ensure_gitignore_creates_new_file(tmp_path: Path):
    root = tmp_path

    msg = g.ensure_gitignore(root, "python")

    path = root / ".gitignore"
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert g.SECTION_START in text
    assert "# Python" in text
    assert ".securegitx.toml" in text
    assert "Created .gitignore" in msg


def test_ensure_gitignore_preserves_user_content_and_appends_section(tmp_path: Path):
    root = tmp_path
    original = "custom-line\nanother-rule/\n"
    (root / ".gitignore").write_text(original, encoding="utf-8")

    msg = g.ensure_gitignore(root, "node")

    text = (root / ".gitignore").read_text(encoding="utf-8")
    assert "custom-line" in text
    assert "another-rule/" in text
    assert g.SECTION_START in text
    assert "# Node" in text
    assert "Appended SecureGitX section" in msg


def test_ensure_gitignore_updates_existing_managed_section(tmp_path: Path):
    root = tmp_path
    (root / ".gitignore").write_text(
        "\n".join(
            [
                "user-rule/",
                "",
                g.SECTION_START,
                "",
                "# SecureGitX local state",
                ".securegitx/",
                ".securegitx.toml",
                "",
                "# Security — credentials and keys",
                "*.env",
                "",
                "# Python",
                "__pycache__/",
                g.SECTION_END,
                "",
            ]
        ),
        encoding="utf-8",
    )

    msg = g.ensure_gitignore(root, "python", extra_entries=["secrets/generated.key"])

    text = (root / ".gitignore").read_text(encoding="utf-8")
    assert "user-rule/" in text
    assert g.SECTION_START in text
    assert "secrets/generated.key" in text
    assert "Updated SecureGitX section" in msg


def test_ensure_gitignore_is_idempotent_when_already_current(tmp_path: Path):
    root = tmp_path
    g.ensure_gitignore(root, "go")
    before = (root / ".gitignore").read_text(encoding="utf-8")

    msg = g.ensure_gitignore(root, "go")
    after = (root / ".gitignore").read_text(encoding="utf-8")

    assert before == after
    assert "already up to date" in msg


def test_add_entry_appends_daemon_suggestion(tmp_path: Path):
    root = tmp_path
    g.ensure_gitignore(root, "generic")

    msg = g.add_entry(root, "logs/debug-secret.txt", "generic")

    text = (root / ".gitignore").read_text(encoding="utf-8")
    assert "logs/debug-secret.txt" in text
    assert "Detected by SecureGitX daemon" in text
    assert "Updated SecureGitX section" in msg or "Created .gitignore" in msg


def test_add_entry_is_noop_if_entry_already_present(tmp_path: Path):
    root = tmp_path
    g.ensure_gitignore(root, "python")

    first = g.add_entry(root, "secrets/api.key", "python")
    text1 = (root / ".gitignore").read_text(encoding="utf-8")

    second = g.add_entry(root, "secrets/api.key", "python")
    text2 = (root / ".gitignore").read_text(encoding="utf-8")

    assert text1 == text2
    assert "Already in .gitignore" in second or "Updated SecureGitX section" in first


def test_add_entry_preserves_existing_daemon_entries(tmp_path: Path):
    root = tmp_path
    g.ensure_gitignore(root, "generic", extra_entries=["tmp/one.secret"])

    g.add_entry(root, "tmp/two.secret", "generic")

    text = (root / ".gitignore").read_text(encoding="utf-8")
    assert "tmp/one.secret" in text
    assert "tmp/two.secret" in text


def test_strip_managed_section_removes_only_managed_block():
    text = "\n".join(
        [
            "user-rule/",
            "",
            g.SECTION_START,
            "",
            ".securegitx/",
            ".securegitx.toml",
            "",
            g.SECTION_END,
            "",
            "keep-this-too/",
        ]
    )

    stripped = g._strip_managed_section(text)

    assert "user-rule/" in stripped
    assert "keep-this-too/" in stripped
    assert g.SECTION_START not in stripped
    assert g.SECTION_END not in stripped
    assert ".securegitx/" not in stripped
