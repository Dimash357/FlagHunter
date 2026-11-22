#!/usr/bin/env bash
# FlagHunter setup for Linux / Kali.
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"
echo "[*] Using $("$PY" --version)"

if [ ! -d .venv ]; then
  echo "[*] Creating virtualenv (.venv)"
  "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
. .venv/bin/activate

echo "[*] Installing requirements"
python -m pip install --upgrade pip >/dev/null
python -m pip install -r requirements.txt

if [ ! -f .env ]; then
  cp .env.example .env
  echo "[*] Created .env (edit it to add an optional GEMINI_API_KEY)"
fi

echo "[*] Running tests"
python -m unittest discover -s tests -v

cat <<'MSG'

[+] Setup complete. Activate the venv and run FlagHunter:

    . .venv/bin/activate

    # Scan an authorised CTF challenge on a VPN lab:
    python -m flaghunter --url http://10.10.14.7:8080/ --authorized --allow-private --active

    # Launch the dashboard:
    uvicorn flaghunter.web:app --host 127.0.0.1 --port 8787
    # open http://127.0.0.1:8787

MSG
