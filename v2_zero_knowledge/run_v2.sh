#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
python -m pip install -q -r requirements.txt
echo "[V2] http://127.0.0.1:8002"
python -m uvicorn app:app --host 127.0.0.1 --port 8002
