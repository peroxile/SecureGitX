from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from securegitx import project_detect


def write_file(root: Path, rel: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x", encoding="utf-8")


def test_detect_python_by_manifest(tmp_path: Path):
    root = tmp_path
    write_file(root, "pyproject.toml")

    info = project_detect.detect(root)

    assert info.type == "python"
    assert info.confidence == "high"
    assert "pyproject.toml" in info.markers


def test_detect_node_by_manifest(tmp_path: Path):
    root = tmp_path
    write_file(root, "package.json")

    info = project_detect.detect(root)

    assert info.type == "node"
    assert info.confidence == "high"
    assert "package.json" in info.markers


def test_detect_first_match_wins_when_multiple_manifests_exist(tmp_path: Path):
    root = tmp_path
    write_file(root, "pyproject.toml")
    write_file(root, "package.json")

    info = project_detect.detect(root)

    assert info.type == "python"
    assert info.confidence == "high"
    assert "pyproject.toml" in info.markers
    assert "package.json" in info.markers


def test_detect_go_by_manifest(tmp_path: Path):
    root = tmp_path
    write_file(root, "go.mod")

    info = project_detect.detect(root)

    assert info.type == "go"
    assert info.confidence == "high"
    assert "go.mod" in info.markers


def test_detect_rust_by_manifest(tmp_path: Path):
    root = tmp_path
    write_file(root, "Cargo.toml")

    info = project_detect.detect(root)

    assert info.type == "rust"
    assert info.confidence == "high"
    assert "Cargo.toml" in info.markers


def test_detect_java_by_manifest(tmp_path: Path):
    root = tmp_path
    write_file(root, "pom.xml")

    info = project_detect.detect(root)

    assert info.type == "java"
    assert info.confidence == "high"
    assert "pom.xml" in info.markers


def test_detect_php_by_manifest(tmp_path: Path):
    root = tmp_path
    write_file(root, "composer.json")

    info = project_detect.detect(root)

    assert info.type == "php"
    assert info.confidence == "high"
    assert "composer.json" in info.markers


def test_detect_node_by_extension_heuristic(monkeypatch, tmp_path: Path):
    root = tmp_path

    fake_ls_files = SimpleNamespace(
        returncode=0,
        stdout="\n".join(
            [
                "src/app.ts",
                "src/main.tsx",
                "src/lib.jsx",
                "src/other.js",
                "README.md",
            ]
        ),
    )

    monkeypatch.setattr(project_detect.subprocess, "run", lambda *a, **k: fake_ls_files)

    info = project_detect.detect(root)

    assert info.type == "node"
    assert info.confidence == "low"
    assert info.markers
    assert "*.ts" in info.markers[0] or "*.js" in info.markers[0]


def test_detect_python_by_extension_heuristic(monkeypatch, tmp_path: Path):
    root = tmp_path

    fake_ls_files = SimpleNamespace(
        returncode=0,
        stdout="\n".join(
            [
                "src/app.py",
                "src/plugin.pyi",
                "src/native.pyx",
                "README.md",
            ]
        ),
    )

    monkeypatch.setattr(project_detect.subprocess, "run", lambda *a, **k: fake_ls_files)

    info = project_detect.detect(root)

    assert info.type == "python"
    assert info.confidence == "low"
    assert info.markers
    assert "*.py" in info.markers[0] or "*.pyi" in info.markers[0]


def test_detect_generic_when_no_markers_and_unknown_extensions(
    monkeypatch, tmp_path: Path
):
    root = tmp_path

    fake_ls_files = SimpleNamespace(
        returncode=0,
        stdout="\n".join(
            [
                "assets/logo.png",
                "docs/readme.md",
                "data/sample.json",
            ]
        ),
    )

    monkeypatch.setattr(project_detect.subprocess, "run", lambda *a, **k: fake_ls_files)

    info = project_detect.detect(root)

    assert info.type == "generic"
    assert info.confidence == "low"
    assert info.markers == []


def test_detect_generic_when_git_ls_files_fails(monkeypatch, tmp_path: Path):
    root = tmp_path

    def raise_error(*args, **kwargs):
        raise OSError("git unavailable")

    monkeypatch.setattr(project_detect.subprocess, "run", raise_error)

    info = project_detect.detect(root)

    assert info.type == "generic"
    assert info.confidence == "low"
    assert info.markers == []


def test_count_extensions_ignores_files_without_extension(monkeypatch, tmp_path: Path):
    root = tmp_path

    fake_ls_files = SimpleNamespace(
        returncode=0,
        stdout="\n".join(
            [
                "Dockerfile",
                "Makefile",
                "src/app.py",
                "src/main.go",
                "README",
            ]
        ),
    )

    monkeypatch.setattr(project_detect.subprocess, "run", lambda *a, **k: fake_ls_files)

    counts = project_detect._count_extensions(root)

    assert counts == {"py": 1, "go": 1}
