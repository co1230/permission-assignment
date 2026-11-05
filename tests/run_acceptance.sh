#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."
echo "=== V1 验收 ==="
python tests/acceptance_v1.py
echo
echo "=== V2 验收 ==="
node tests/acceptance_v2.mjs
