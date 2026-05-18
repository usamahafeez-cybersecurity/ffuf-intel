#!/usr/bin/env bash
# Remove local build artifacts before git push
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
rm -rf .venv ffuf_intel/.venv ffuf_intel.egg-info dist build .pytest_cache .mypy_cache .ruff_cache
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find . -name '*.pyc' -delete 2>/dev/null || true
rm -f tools/ffuf tools/ffuf.exe 2>/dev/null || true
echo "Done. Safe to: git add . && git commit"
