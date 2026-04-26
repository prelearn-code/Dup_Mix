from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.chain import connect_chain, deploy_contract
from src.crypto import CryptoEngine, setup
from src.local_client_store import save_retrieved_file, save_upload_record, save_user_profile
from src.local_csp_store import load_csp_state, save_csp_state
from src.models import UserState
from src.protocol import audit_req, ownership_transfer_protocol, proof_gen, retrieve_protocol, upload_and_dedup_protocol, verify_proof_protocol
from src.utils import compressed_public_key_from_private, load_environment


CLIENT_FILES = ROOT / "data" / "client_files"
CLIENT_DB = ROOT / "data" / "client_db"
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


def _ordered_client_files() -> list[Path]:
    CLIENT_FILES.mkdir(parents=True, exist_ok=True)
    manifest_path = CLIENT_FILES / "manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        files = []
        for item in manifest.get("files", []):
            name = item.get("name")
            if not name:
                continue
            path = CLIENT_FILES / name
            if path.is_file():
                files.append(path)
        if files:
            return files
    return sorted(
        path
        for path in CLIENT_FILES.iterdir()
        if path.is_file() and not path.name.startswith(".") and path.name != "manifest.json"
    )


def _selected_client_files(count: int) -> list[Path]:
    candidates = _ordered_client_files()
    if not candidates:
        raise FileNotFoundError(
            f"No client file found in {CLIENT_FILES}. Put a real file in this directory and rerun."
        )
    return candidates[: max(1, count)]


def _public_blocks_for_file(file_bytes: bytes) -> list[int]:
    return [0] if file_bytes else []


def _print(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))


def _log(message: str) -> None:
    print(message, flush=True)


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


def _gamma_for_block(csp: Any, block_id: str) -> int:
    for file_state in csp.files.values():
        if block_id in file_state.block_ids:
            return int(file_state.metadata.get("gamma", 19))
    return 19


def _repair_authenticators_if_needed(csp: Any, engine: CryptoEngine) -> bool:
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


def _run_one_file(
    source_path: Path,
    index: int,
    total: int,
    owner: UserState,
    buyer: UserState,
    csp: Any,
    chain: Any,
    engine: CryptoEngine,
) -> dict[str, Any]:
    file_bytes = source_path.read_bytes()
    _log(f"[client] selected file {index}/{total}: {source_path} ({len(file_bytes)} bytes)")

    upload = upload_and_dedup_protocol(
        owner,
        file_bytes,
        csp,
        chain,
        engine,
        public_block_indices=_public_blocks_for_file(file_bytes),
    )
    block_count = int(upload.get("block_count", len(upload.get("block_ids", []))))
    duplicate_block_count = int(upload.get("duplicate_block_count", 0))
    new_block_count = int(upload.get("new_block_count", max(0, block_count - duplicate_block_count)))
    if upload.get("duplicate_file"):
        _log(
            "[dedup] file duplicate: "
            f"yes, existing_file_id={upload.get('duplicate_file_id')} "
            f"blocks_reused={duplicate_block_count}/{block_count}"
        )
    else:
        _log("[dedup] file duplicate: no")
    _log(
        "[dedup] block summary for this file: "
        f"total={block_count} duplicate={duplicate_block_count} new={new_block_count}"
    )

    file_state = csp.files[upload["file_id"]]
    chain_upload_record = chain.uploads.get(upload["file_id"], {})
    owner_record = save_upload_record(CLIENT_DB, owner, source_path, upload, file_state, chain_upload_record)
    _log(
        "[upload] stored file: "
        f"file_id={upload['file_id']} root={file_state.mht_root} "
        f"chain_status={chain_upload_record.get('status', 'mock')}"
    )
    _log(
        "[csp] database after upload: "
        f"files={len(csp.files)} blocks={len(csp.blocks)} "
        f"authenticators={len(csp.authenticators)} key_cipher_blocks={len(csp.key_ciphers)}"
    )

    challenge = audit_req(
        upload["file_id"],
        len(file_state.block_ids),
        engine,
        chain_state=chain,
        requester=owner.address,
        z_value=min(2, len(file_state.block_ids)),
    )
    proof = proof_gen(challenge, file_state, csp, engine)
    _log(
        "[audit] proof generated: "
        f"challenge_id={challenge['challenge_id']} z={challenge['z']} "
        f"indices={proof['indices']}"
    )
    verified = verify_proof_protocol(proof, challenge, file_state, csp, chain, engine)
    _log(
        "[audit] verification result: "
        f"verified={verified} chain_result={chain.proof_results.get(challenge['challenge_id'], {})}"
    )

    recovered = retrieve_protocol(owner, upload["file_id"], csp, engine, owner.UID, owner.W)
    retrieved_path = save_retrieved_file(CLIENT_DB, upload["file_id"], recovered)
    _log(f"[retrieve] owner recovered file: match={recovered == file_bytes} path={retrieved_path}")
    transfer = ownership_transfer_protocol(owner, buyer, upload["file_id"], csp, chain, engine)
    _log(
        "[transfer] ownership transfer: "
        f"success={transfer['success']} old_owner={transfer['old_owner']} new_owner={transfer['new_owner']}"
    )
    buyer_recovered = retrieve_protocol(buyer, upload["file_id"], csp, engine, buyer.UID, buyer.W)
    buyer_retrieved_path = save_retrieved_file(CLIENT_DB, f"{upload['file_id']}.buyer", buyer_recovered)
    _log(f"[retrieve] buyer recovered file: match={buyer_recovered == file_bytes} path={buyer_retrieved_path}")

    save_upload_record(CLIENT_DB, buyer, source_path, upload, csp.files[upload["file_id"]], chain_upload_record)
    save_csp_state(csp, CSP_DB, engine.params)
    _log(f"[csp] database saved: {CSP_DB}")

    return {
        "source_file": str(source_path),
        "file_id": upload["file_id"],
        "duplicate_file": upload["duplicate_file"],
        "duplicate_file_id": upload.get("duplicate_file_id"),
        "block_count": len(file_state.block_ids),
        "duplicate_block_count": duplicate_block_count,
        "new_block_count": new_block_count,
        "csp_file_index_size": len(csp.file_index),
        "csp_block_index_size": len(csp.block_index),
        "authenticator_count": len(csp.authenticators),
        "chain_upload_record": chain_upload_record,
        "audit_verified": verified,
        "chain_proof_result": chain.proof_results.get(challenge["challenge_id"], {}),
        "owner_retrieve_match": recovered == file_bytes,
        "owner_retrieved_path": str(retrieved_path),
        "transfer_success": transfer["success"],
        "buyer_retrieve_match": buyer_recovered == file_bytes,
        "buyer_retrieved_path": str(buyer_retrieved_path),
        "upload_record": str(CLIENT_DB / "uploads" / f"{owner_record['file_id']}.json"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run real-chain full flow for the first N files in data/client_files.")
    parser.add_argument("--count", type=int, default=1, help="Number of ordered client files to process. Default: 1.")
    args = parser.parse_args()

    load_environment()
    source_paths = _selected_client_files(args.count)
    _log(f"[client] selected {len(source_paths)} file(s) from {CLIENT_FILES}")

    owner = _build_user("USER1_ADDRESS", "USER1_PRIVATE_KEY", "client-owner")
    buyer = _build_user("USER2_ADDRESS", "USER2_PRIVATE_KEY", "client-buyer")
    csp_address = _env("CSP_ADDRESS")
    csp_private_key = _env("CSP_PRIVATE_KEY")

    engine = CryptoEngine(setup(sectors_per_block=128, s=b"real-file-full-flow"))
    chain = deploy_contract(
        connect_chain(chain_id=int(os.getenv("GANACHE_CHAIN_ID", "1337")), require_real=True),
        str(ROOT / "contracts" / "AuditSystem.sol"),
    )
    csp = load_csp_state(CSP_DB, csp_address, csp_private_key, storage_capacity=10**12)
    repaired_authenticators = _repair_authenticators_if_needed(csp, engine)
    _log(
        "[csp] loaded database: "
        f"files={len(csp.files)} blocks={len(csp.blocks)} "
        f"file_index={len(csp.file_index)} block_index={len(csp.block_index)}"
    )
    if repaired_authenticators:
        _log("[csp] repaired persisted HVT authenticators for current stable setup parameters")

    save_user_profile(CLIENT_DB, owner)
    save_user_profile(CLIENT_DB, buyer)
    _log(f"[client] user profiles saved under {CLIENT_DB}")

    results = [
        _run_one_file(source_path, index, len(source_paths), owner, buyer, csp, chain, engine)
        for index, source_path in enumerate(source_paths, start=1)
    ]

    _print(
        {
            "flow": "real_file_full_flow",
            "chain_backend": chain.backend,
            "contract_address": chain.contract_address,
            "processed_count": len(results),
            "client_db": str(CLIENT_DB),
            "csp_db": str(CSP_DB),
            "summary": {
                "duplicate_files": sum(1 for item in results if item["duplicate_file"]),
                "total_blocks": sum(item["block_count"] for item in results),
                "duplicate_blocks": sum(item["duplicate_block_count"] for item in results),
                "new_blocks": sum(item["new_block_count"] for item in results),
                "audit_success": sum(1 for item in results if item["audit_verified"]),
                "owner_retrieve_success": sum(1 for item in results if item["owner_retrieve_match"]),
                "transfer_success": sum(1 for item in results if item["transfer_success"]),
                "buyer_retrieve_success": sum(1 for item in results if item["buyer_retrieve_match"]),
            },
            "results": results,
        }
    )


if __name__ == "__main__":
    main()
