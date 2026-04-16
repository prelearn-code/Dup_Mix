from __future__ import annotations

import argparse
import sys
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.paper_tests.common import ensure_results_dir, write_csv, write_json
from scripts.paper_tests.web3_gas_utils import connect_web3, deploy_audit_system, send_tx_and_gas


def main() -> None:
    parser = argparse.ArgumentParser(description="Metric I: real-chain gas for ownership transfer phases")
    parser.add_argument("--fee3", type=int, default=9)
    args = parser.parse_args()

    try:
        w3 = connect_web3()
        contract = deploy_audit_system(w3)
    except Exception as exc:
        print(f"[I] setup failed: {exc}", flush=True)
        print("[I] require Ganache RPC and local solc (.solcx or ~/.solcx) for real-chain gas benchmark.", flush=True)
        raise SystemExit(2)
    accounts = w3.eth.accounts
    from_owner = accounts[0]
    to_owner = accounts[1] if len(accounts) > 1 else accounts[0]
    csp = accounts[2] if len(accounts) > 2 else accounts[0]

    file_id = f"file-{uuid4().hex[:8]}"

    print("[I] measuring transfer request gas...", flush=True)
    request_tx = send_tx_and_gas(
        w3,
        contract.functions.requestTransfer(file_id, from_owner, to_owner, args.fee3),
        to_owner,
    )

    print("[I] measuring owner verification gas...", flush=True)
    owner_attestation = w3.keccak(text=f"owner-proof:{file_id}:{from_owner}")
    owner_verify_tx = send_tx_and_gas(
        w3,
        contract.functions.benchmarkVerifyTransferOwner(file_id, from_owner, owner_attestation),
        from_owner,
    )

    print("[I] measuring CSP update gas...", flush=True)
    ownership_root = w3.keccak(text=f"ownership-root:{file_id}:{to_owner}")
    csp_update_tx = send_tx_and_gas(
        w3,
        contract.functions.benchmarkCspUpdateTransfer(file_id, ownership_root),
        csp,
    )

    print("[I] measuring finalize gas...", flush=True)
    finalize_tx = send_tx_and_gas(
        w3,
        contract.functions.benchmarkFinalizeTransfer(file_id, True),
        to_owner,
    )

    row = {
        "metric": "I",
        "contract": contract.address,
        "request_gas": request_tx["gas_used"],
        "owner_verify_gas": owner_verify_tx["gas_used"],
        "csp_update_gas": csp_update_tx["gas_used"],
        "finalize_gas": finalize_tx["gas_used"],
    }
    result = {"name": "I_transfer_gas", "rows": [row]}
    out_dir = ensure_results_dir()
    csv_path = out_dir / "I_transfer_gas.csv"
    json_path = out_dir / "I_transfer_gas.json"
    write_csv(csv_path, [row])
    write_json(json_path, result)
    print(f"[I] done. csv={csv_path} json={json_path}", flush=True)


if __name__ == "__main__":
    main()
