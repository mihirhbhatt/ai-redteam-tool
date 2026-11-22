"""Prepare a distributable executable folder with its external configuration."""

import argparse
from pathlib import Path
import shutil


def package_release(root: Path, destination: Path) -> None:
    executable_dir = root / "dist" / "ai-redteam"
    config_dir = root / "config"
    if not executable_dir.is_dir():
        raise FileNotFoundError(f"Executable build not found: {executable_dir}")
    if not config_dir.is_dir():
        raise FileNotFoundError(f"Configuration directory not found: {config_dir}")
    if destination.exists():
        raise FileExistsError(f"Release destination already exists: {destination}")
    shutil.copytree(executable_dir, destination)
    shutil.copytree(config_dir, destination / "config")
    shutil.copy2(root / "README.md", destination / "README.md")
    shutil.copy2(root / "scripts" / "Open Dashboard.cmd", destination / "Open Dashboard.cmd")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    package_release(Path(__file__).resolve().parent.parent, args.destination)


if __name__ == "__main__":
    main()
