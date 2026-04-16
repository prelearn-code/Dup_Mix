#!/usr/bin/env bash
set -euo pipefail

echo "== DupMix paper repro setup =="
/usr/bin/python3 --version

if [ ! -f ".env" ] && [ -f ".env.example" ]; then
  cp .env.example .env
  echo ".env created from .env.example"
fi

if [ ! -d ".venv" ]; then
  /usr/bin/python3 -m venv .venv
fi

./.venv/bin/pip install --upgrade pip
./.venv/bin/pip install -r requirements.txt

echo ""
echo "== Baseline environment ready =="
echo "Running strict paper repro check..."
./.venv/bin/python scripts/check_paper_env.py

echo ""
echo "Tips:"
echo "1) For strict FULL_REPRO, ensure libpbc/libgmp are installed and Ganache RPC is running."
echo "2) Start Ganache (if needed):"
echo '   ganache --wallet.mnemonic "copper wave move caught main cruise derive inherit team sister make escape" --chain.chainId 1337 --chain.hardfork shanghai --server.host 127.0.0.1 --server.port 7545'
