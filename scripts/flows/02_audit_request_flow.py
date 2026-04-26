from __future__ import annotations

import argparse
import json
import os
import random
import secrets
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.chain import connect_chain, deploy_contract
from src.crypto import CryptoEngine, setup
from src.local_csp_store import load_csp_state
from src.models import CSPState, FileState, UserState
from src.protocol import audit_req, proof_gen, verify_proof_protocol
from src.utils import compressed_public_key_from_private, load_environment


CSP_DB = ROOT / "data" / "csp_db"


def _env(name: str, default: str = "") -> str:
    value = os.getenv(name, default)
    if not value:
        raise RuntimeError(f"Missing required environment value: {name}")
    return value


def _build_user(address_key: str, private_key_key: str, uid: str) -> UserState:
    private_key = _env(private_key_key)
    return UserState(
        address=_env(address_key),
        private_key=private_key,
        uid=uid,
        public_key=compressed_public_key_from_private(private_key),
    )


def _print(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))


def _current_crypto_manifest(engine: CryptoEngine) -> dict[str, Any]:
    return {
        "s_param": engine.params.s_param.hex(),
        "group_order": engine.params.group_order,
        "generator": engine.params.generator,
        "r_values": engine.params.r_values,
        "sectors_per_block": engine.params.sectors_per_block,
        "pairing_backend": engine.params.pairing_backend,
    }


def _stored_crypto_manifest() -> dict[str, Any]:
    path = CSP_DB / "manifest.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8")).get("crypto_params", {})


def _gamma_for_block(csp: CSPState, block_id: str) -> int:
    for file_state in csp.files.values():
        if block_id in file_state.block_ids:
            return int(file_state.metadata.get("gamma", 19))
    return 19


def _repair_authenticators_if_needed(csp: CSPState, engine: CryptoEngine) -> bool:
    if not csp.blocks:
        return False
    if _stored_crypto_manifest() == _current_crypto_manifest(engine):
        return False
    for block_id, block in csp.blocks.items():
        gamma = _gamma_for_block(csp, block_id)
        tag = int(block["tag"], 16)
        y_i, y_group, sigma_i = engine.authgen(block["sectors"], tag, block["sector_keys"], gamma)
        csp.authenticators[block_id] = {"sigma": sigma_i, "y": y_i, "Y": y_group}
    return True


def _ordered_files(csp: CSPState) -> list[FileState]:
    return sorted(csp.files.values(), key=lambda item: item.file_id)


def _select_files(csp: CSPState, file_id: str | None, audit_all: bool, rng: random.Random) -> tuple[list[FileState], int]:
    candidates = _ordered_files(csp)
    if not candidates:
        raise FileNotFoundError(f"No uploaded files found in {CSP_DB}. Run upload/full flow first.")
    if file_id:
        selected = csp.files.get(file_id)
        if selected is None:
            raise KeyError(f"file_id not found in CSP DB: {file_id}")
        return [selected], len(candidates)
    if audit_all:
        return candidates, len(candidates)
    return [rng.choice(candidates)], len(candidates)


def _random_challenge_size(file_state: FileState, max_challenge_blocks: int | None, rng: random.Random) -> int:
    n_blocks = len(file_state.block_ids)
    upper = n_blocks if max_challenge_blocks is None else min(max_challenge_blocks, n_blocks)
    return rng.randint(1, max(1, upper))


def _audit_one(
    file_state: FileState,
    csp: CSPState,
    chain: Any,
    engine: CryptoEngine,
    requester: UserState,
    z_value: int,
) -> dict[str, Any]:
    challenge = audit_req(
        file_state.file_id,
        len(file_state.block_ids),
        engine,
        chain_state=chain,
        requester=requester.address,
        z_value=z_value,
    )
    proof = proof_gen(challenge, file_state, csp, engine)
    verified = verify_proof_protocol(proof, challenge, file_state, csp, chain, engine)
    return {
        "file_id": file_state.file_id,
        "owner": file_state.owner_address,
        "file_size": file_state.file_size,
        "block_count": len(file_state.block_ids),
        "z": challenge["z"],
        "challenge_id": challenge["challenge_id"],
        "proof_indices": proof["indices"],
        "proof_coeff_count": len(proof["coeffs"]),
        "proof_digest_hex": proof["proof_digest_hex"],
        "verified": verified,
        "chain_challenge_record": chain.challenges.get(challenge["challenge_id"], {}),
        "chain_proof_result": chain.proof_results.get(challenge["challenge_id"], {}),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Flow 2: standalone audit request over persisted CSP DB. "
            "Default candidate range is every uploaded file; one file and z are chosen randomly."
        )
    )
    parser.add_argument("--mock-chain", action="store_true", help="Use in-memory mock chain instead of Ganache/web3.")
    parser.add_argument("--file-id", default=None, help="Audit one explicit file id from CSP DB.")
    parser.add_argument("--all", action="store_true", help="Audit every file in CSP DB instead of randomly choosing one.")
    parser.add_argument(
        "--max-challenge-blocks",
        type=int,
        default=None,
        help="Upper bound for random z. Default: random z in [1, file block count].",
    )
    parser.add_argument("--seed", type=int, default=None, help="Deterministic random seed for repeatable experiments.")
    args = parser.parse_args()

    load_environment()
    seed = args.seed if args.seed is not None else secrets.randbits(64)
    rng = random.Random(seed)
    engine = CryptoEngine(setup(sectors_per_block=128, s=b"real-file-full-flow"))
    chain = deploy_contract(
        connect_chain(
            chain_id=int(os.getenv("GANACHE_CHAIN_ID", "1337")),
            force_mock=args.mock_chain,
            require_real=not args.mock_chain,
        ),
        str(ROOT / "contracts" / "AuditSystem.sol"),
    )
    csp = load_csp_state(CSP_DB, _env("CSP_ADDRESS"), _env("CSP_PRIVATE_KEY"), storage_capacity=10**12)
    repaired_authenticators = _repair_authenticators_if_needed(csp, engine)
    requester = _build_user("USER1_ADDRESS", "USER1_PRIVATE_KEY", "audit-requester")
    selected_files, candidate_count = _select_files(csp, args.file_id, args.all, rng)

    results = []
    for file_state in selected_files:
        z_value = _random_challenge_size(file_state, args.max_challenge_blocks, rng)
        results.append(_audit_one(file_state, csp, chain, engine, requester, z_value))

    _print(
        {
            "flow": "audit_request",
            "chain_backend": chain.backend,
            "contract_address": chain.contract_address,
            "selection_policy": "explicit_file" if args.file_id else ("all_files" if args.all else "random_file_from_all_files"),
            "random_seed": seed,
            "candidate_file_count": candidate_count,
            "selected_file_count": len(selected_files),
            "repaired_authenticators": repaired_authenticators,
            "steps": [
                "load all uploaded file states from data/csp_db",
                "include every file in the audit candidate range",
                "randomly select file unless --file-id or --all is provided",
                "randomly select challenge block count z for each selected file",
                "create audit request on chain/mock chain",
                "CSP generates proof from challenged blocks",
                "verifier recomputes challenge indices and pairing relation",
                "chain records verification result and settlement state",
            ],
            "results": results,
            "summary": {
                "audit_success": sum(1 for item in results if item["verified"]),
                "audit_failed": sum(1 for item in results if not item["verified"]),
            },
        }
    )


if __name__ == "__main__":
    main()
