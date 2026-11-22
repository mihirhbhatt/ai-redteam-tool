from pathlib import Path

import pytest

from scripts.package_release import package_release


def test_release_contains_executable_config_and_readme(tmp_path: Path):
    root = tmp_path / "source"
    executable = root / "dist" / "ai-redteam"
    config = root / "config" / "judge_prompts"
    executable.mkdir(parents=True)
    config.mkdir(parents=True)
    (executable / "ai-redteam").write_text("executable", encoding="utf-8")
    (config / "judge_templates.yaml").write_text("templates", encoding="utf-8")
    (root / "README.md").write_text("readme", encoding="utf-8")
    (root / "scripts").mkdir()
    (root / "scripts" / "Open Dashboard.cmd").write_text("launcher", encoding="utf-8")
    destination = tmp_path / "release" / "ai-redteam"

    package_release(root, destination)

    assert (destination / "ai-redteam").read_text() == "executable"
    assert (destination / "config" / "judge_prompts" / "judge_templates.yaml").exists()
    assert (destination / "README.md").exists()
    assert (destination / "Open Dashboard.cmd").read_text() == "launcher"
    with pytest.raises(FileExistsError):
        package_release(root, destination)


def test_release_requires_a_build(tmp_path: Path):
    with pytest.raises(FileNotFoundError, match="Executable build not found"):
        package_release(tmp_path, tmp_path / "release")
