#!/usr/bin/env bash
# One-command installer for source checkout (macOS / Linux).
# Creates a venv, installs core deps + WebEngine, and adds a desktop launcher script.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3}"
VENV="$ROOT/.venv"

echo "==> Creating virtual environment"
"$PYTHON" -m venv "$VENV"
# shellcheck disable=SC1091
source "$VENV/bin/activate"

echo "==> Installing RevENG dependencies"
pip install --upgrade pip
pip install -r requirements.txt
pip install PyQt6-WebEngine

LAUNCHER="$ROOT/RevENG"
cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
cd "$ROOT"
source "$VENV/bin/activate"
exec python main.py "\$@"
EOF
chmod +x "$LAUNCHER"

echo ""
echo "Installation complete."
echo "  Run the app:  ./RevENG"
echo "  Or:           $VENV/bin/python main.py"
echo ""
echo "Optional power features: pip install -r requirements-optional.txt"
