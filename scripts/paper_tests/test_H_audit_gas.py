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
    parser = argparse.ArgumentParser(description="Metric H: real-chain gas for audit phases")
    parser.add_argument("--fee2", type=int, default=7)
    parser.add_argument("--fee1", type=int, default=12)
    args = parser.parse_args()

    try:
        w3 = connect_web3()
        contract = deploy_audit_system(w3)
    except Exception as exc:
        print(f"[H] setup failed: {exc}", flush=True)
        print("[H] require Ganache RPC and local solc (.solcx or ~/.solcx) for real-chain gas benchmark.", flush=True)
        raise SystemExit(2)
    accounts = w3.eth.accounts
    owner = accounts[0]
    requester = accounts[1] if len(accounts) > 1 else accounts[0]
    csp = accounts[2] if len(accounts) > 2 else accounts[0]

    file_id = f"file-{uuid4().hex[:8]}"
    challenge_id = f"chal-{uuid4().hex[:8]}"

    print("[H] deployed contract, preparing upload record...", flush=True)
    send_tx_and_gas(
        w3,
        contract.functions.recordUpload(file_id, owner, "t-value", "root0", 10, 25),
        owner,
    )

    print("[H] measuring challenge phase gas...", flush=True)
    challenge_tx = send_tx_and_gas(
        w3,
        contract.functions.createAuditRequest(challenge_id, file_id, requester, 460),
        requester,
    )

    print("[H] measuring prove phase gas...", flush=True)
    proof_blob = (b"paper-proof-payload|" * 48)[:1024]
    proof_checksum = sum((idx + 1) * b for idx, b in enumerate(proof_blob))
    prove_tx = send_tx_and_gas(
        w3,
        contract.functions.benchmarkSubmitProof(challenge_id, proof_blob, proof_checksum),
        csp,
    )

    print("[H] measuring verify phase gas...", flush=True)
    verify_tx = send_tx_and_gas(
        w3,
        contract.functions.benchmarkVerifyProofAndSettle(
            challenge_id,
            owner,
            csp,
            proof_checksum,
            args.fee2,
            args.fee1,
            proof_blob,
        ),
        requester,
    )

    row = {
        "metric": "H",
        "contract": contract.address,
        "challenge_gas": challenge_tx["gas_used"],
        "prove_gas": prove_tx["gas_used"],
        "verify_gas": verify_tx["gas_used"],
    }
    result = {"name": "H_audit_gas", "rows": [row]}
    out_dir = ensure_results_dir()
    csv_path = out_dir / "H_audit_gas.csv"
    json_path = out_dir / "H_audit_gas.json"
    write_csv(csv_path, [row])
    write_json(json_path, result)
    print(f"[H] done. csv={csv_path} json={json_path}", flush=True)


if __name__ == "__main__":
    main()
