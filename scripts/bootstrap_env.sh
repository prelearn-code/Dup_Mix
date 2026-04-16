#!/usr/bin/env bash
set -euo pipefail

echo "Bootstrapping DupMixSystem environment..."
/usr/bin/python3 --version

if [ ! -d ".venv" ]; then
  /usr/bin/python3 -m venv .venv
fi

./.venv/bin/pip install --upgrade pip
./.venv/bin/pip install -r requirements.txt

echo "Checking native libraries..."
if ldconfig -p | grep -q libgmp.so; then
  echo "libgmp.so found"
else
  echo "libgmp.so missing"
fi

if ldconfig -p | grep -q libpbc.so; then
  echo "libpbc.so found"
else
  echo "libpbc.so missing, runtime will use arithmetic fallback"
fi

echo "Ganache expected at http://127.0.0.1:7545 (chain id 1337)"
echo "Bootstrap complete."
