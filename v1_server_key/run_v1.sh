#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
python -m pip install -q -r requirements.txt
echo "[V1] http://127.0.0.1:8001"
python -m uvicorn app:app --host 127.0.0.1 --port 8001
