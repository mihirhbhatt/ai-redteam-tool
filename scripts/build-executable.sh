#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
python3 -m PyInstaller --noconfirm --clean --onedir --name ai-redteam --hidden-import anthropic main.py
printf '%s\n' 'Built dist/ai-redteam/ai-redteam. Run it from the project directory.'
