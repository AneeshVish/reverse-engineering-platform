#!/usr/bin/env bash
# Build a self-contained RevENG desktop app with PyInstaller.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3}"
VENV="${VENV:-.venv-build}"

echo "==> Creating build venv at $VENV"
"$PYTHON" -m venv "$VENV"
# shellcheck disable=SC1091
source "$VENV/bin/activate"

echo "==> Installing dependencies"
pip install --upgrade pip
pip install -r requirements.txt -r requirements-packaging.txt

echo "==> Building with PyInstaller"
pyinstaller --noconfirm packaging/reveng.spec

if [[ "$(uname -s)" == "Darwin" ]]; then
  OUT="$ROOT/dist/RevENG.app"
  echo ""
  echo "Build complete: $OUT"
  echo "Launch: open \"$OUT\""
else
  OUT="$ROOT/dist/RevENG"
  echo ""
  echo "Build complete: $OUT/RevENG"
  echo "Launch: \"$OUT/RevENG\""
fi

echo ""
echo "Optional: zip for distribution"
if [[ "$(uname -s)" == "Darwin" ]]; then
  (cd dist && zip -r RevENG-macos.zip RevENG.app)
  echo "Created dist/RevENG-macos.zip"
else
  (cd dist && tar -czf RevENG-linux.tar.gz RevENG)
  echo "Created dist/RevENG-linux.tar.gz"
fi
