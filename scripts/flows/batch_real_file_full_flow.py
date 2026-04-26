from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.chain import connect_chain, deploy_contract
from src.crypto import CryptoEngine, setup
from src.local_client_store import reset_client_db, save_retrieved_file, save_upload_record, save_user_profile
from src.local_csp_store import load_csp_state, reset_csp_db, save_csp_state
from src.models import CSPState, UserState
from src.protocol import audit_req, ownership_transfer_protocol, proof_gen, retrieve_protocol, upload_and_dedup_protocol, verify_proof_protocol
from src.utils import compressed_public_key_from_private, load_environment, split_file_into_blocks_and_sectors


CLIENT_FILES = ROOT / "data" / "client_files"
CLIENT_DB = ROOT / "data" / "client_db"
CSP_DB = ROOT / "data" / "csp_db"
RESULTS_DIR = ROOT / "results" / "real_file_batch_flow"


class TraceLogger:
    def __init__(self, output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        self.events_path = output_dir / "events.jsonl"
        self.summary_path = output_dir / "summary.json"
        self._events = self.events_path.open("w", encoding="utf-8")

    def close(self) -> None:
        self._events.close()

    def event(self, stage: str, payload: dict[str, Any]) -> None:
        row = {
            "time": datetime.now(timezone.utc).isoformat(),
            "stage": stage,
            **payload,
        }
        print(f"[{stage}] {self._format(payload)}", flush=True)
        self._events.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        self._events.flush()

    def summary(self, payload: dict[str, Any]) -> None:
        self.summary_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        self.event("summary", payload)

    @staticmethod
    def _format(payload: dict[str, Any]) -> str:
        parts = []
        for key, value in payload.items():
            if isinstance(value, (dict, list)):
                value = json.dumps(value, ensure_ascii=False)
            parts.append(f"{key}={value}")
        return " ".join(parts)


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


def _preview(value: str | bytes, size: int = 16) -> str:
    text = value.hex() if isinstance(value, bytes) else value
    return text[:size]


def _candidate_files(pattern: str, limit: int | None) -> list[Path]:
    CLIENT_FILES.mkdir(parents=True, exist_ok=True)
    files = [
        path
        for path in sorted(CLIENT_FILES.glob(pattern))
        if path.is_file() and not path.name.startswith(".") and path.name != "manifest.json"
    ]
    if limit is not None:
        return files[:limit]
    return files


def _public_blocks_for_count(block_count: int) -> list[int]:
    return [0] if block_count else []


def _chain_gas(record: dict[str, Any] | None) -> int:
    if not record:
        return 0
    return int(record.get("gas_used", 0) or 0)


def _database_counts(csp: CSPState) -> dict[str, int]:
    return {
        "files": len(csp.files),
        "blocks": len(csp.blocks),
        "file_index": len(csp.file_index),
        "block_index": len(csp.block_index),
        "authenticators": len(csp.authenticators),
        "key_cipher_blocks": len(csp.key_ciphers),
    }


def _tree_stats(tree: Any) -> dict[str, int]:
    if not isinstance(tree, dict):
        return {"nodes": 0, "height": 0, "leaves": 0}
    levels = tree.get("levels")
    if isinstance(levels, list) and levels:
        root = levels[-1][0] if levels[-1] else {}
        return {
            "nodes": sum(len(level) for level in levels if isinstance(level, list)),
            "height": len(levels),
            "leaves": int(root.get("lN", len(levels[0])) if isinstance(root, dict) else len(levels[0])),
        }

    def walk(node: dict[str, Any], depth: int) -> tuple[int, int, int]:
        left = node.get("left")
        right = node.get("right")
        is_leaf = not isinstance(left, dict) and not isinstance(right, dict)
        nodes = 1
        leaves = 1 if is_leaf else 0
        height = depth
        for child in (left, right):
            if isinstance(child, dict):
                child_nodes, child_height, child_leaves = walk(child, depth + 1)
                nodes += child_nodes
                leaves += child_leaves
                height = max(height, child_height)
        return nodes, height, leaves

    nodes, height, leaves = walk(tree, 1)
    return {"nodes": nodes, "height": height, "leaves": leaves}


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


def _preflight_upload(
    source_path: Path,
    file_bytes: bytes,
    csp: CSPState,
    engine: CryptoEngine,
    owner: UserState,
) -> dict[str, Any]:
    blocks = split_file_into_blocks_and_sectors(
        data=file_bytes,
        block_size=engine.params.block_size,
        sectors_per_block=engine.params.sectors_per_block,
    )
    public_blocks = _public_blocks_for_count(len(blocks))
    fk, sector_keys = engine.keygen(file_bytes, blocks)
    encrypted_blocks, key_cipher_map = engine.encrypt_blocks(
        blocks,
        sector_keys,
        public_blocks,
        bytes.fromhex(owner.public_key[2:] if owner.public_key.startswith("0x") else owner.public_key),
    )
    t, tags = engine.taggen(encrypted_blocks, fk)
    tag_hexes = [f"{tag:064x}" for tag in tags]
    duplicate_file_id = csp.file_index.get(f"{t:064x}")
    known_tags = set(csp.block_index)
    seen_new_tags: set[str] = set()
    new_indices = []
    duplicate_indices = []
    for index, tag in enumerate(tag_hexes):
        if tag in known_tags or tag in seen_new_tags:
            duplicate_indices.append(index)
        else:
            new_indices.append(index)
            seen_new_tags.add(tag)
    return {
        "source_file": str(source_path.relative_to(ROOT)),
        "file_size": len(file_bytes),
        "block_count": len(blocks),
        "sector_count": len(blocks) * engine.params.sectors_per_block,
        "public_blocks": public_blocks,
        "private_block_count": max(0, len(blocks) - len(public_blocks)),
        "fk_preview": _preview(f"{fk:064x}"),
        "t": f"{t:064x}",
        "t_preview": _preview(f"{t:064x}"),
        "tag_count": len(tag_hexes),
        "tag_previews": [_preview(tag) for tag in tag_hexes[:5]],
        "key_cipher_count": len(key_cipher_map),
        "duplicate_file_predicted": duplicate_file_id is not None,
        "duplicate_file_id_predicted": duplicate_file_id,
        "duplicate_block_count_predicted": len(duplicate_indices),
        "new_block_count_predicted": len(new_indices),
        "duplicate_indices_preview": duplicate_indices[:10],
        "new_indices_preview": new_indices[:10],
    }


def _run_audit(
    trace: TraceLogger,
    file_id: str,
    file_state: Any,
    csp: CSPState,
    chain: Any,
    engine: CryptoEngine,
    owner: UserState,
    challenge_blocks: int,
) -> tuple[bool, int]:
    z_value = min(challenge_blocks, len(file_state.block_ids))
    challenge = audit_req(file_id, len(file_state.block_ids), engine, chain_state=chain, requester=owner.address, z_value=z_value)
    challenge_tx = chain.challenges.get(challenge["challenge_id"], {})
    trace.event(
        "audit:request",
        {
            "file_id": file_id,
            "challenge_id": challenge["challenge_id"],
            "z": challenge["z"],
            "theta1_preview": _preview(f"{challenge['theta1']:064x}"),
            "theta2_preview": _preview(f"{challenge['theta2']:064x}"),
            "chain_tx": challenge_tx,
        },
    )
    proof = proof_gen(challenge, file_state, csp, engine)
    trace.event(
        "audit:proof",
        {
            "file_id": file_id,
            "challenge_id": challenge["challenge_id"],
            "indices_preview": proof["indices"][:20],
            "indices_count": len(proof["indices"]),
            "coeff_count": len(proof["coeffs"]),
            "P_count": len(proof["P"]),
            "sigma_c_preview": _preview(f"{proof['sigma_c']:064x}"),
            "proof_digest": proof["proof_digest_hex"],
        },
    )
    verified = verify_proof_protocol(proof, challenge, file_state, csp, chain, engine)
    result = chain.proof_results.get(challenge["challenge_id"], {})
    trace.event(
        "audit:verify",
        {
            "file_id": file_id,
            "challenge_id": challenge["challenge_id"],
            "local_pbc_verified": verified,
            "pairing_backend": engine.params.pairing_backend,
            "pairing_strict": engine.params.pairing_strict,
            "chain_result": result,
        },
    )
    return verified, _chain_gas(challenge_tx) + _chain_gas(result)


def _run_retrieve(
    trace: TraceLogger,
    label: str,
    user: UserState,
    file_id: str,
    expected_bytes: bytes,
    csp: CSPState,
    engine: CryptoEngine,
) -> bool:
    file_state = csp.files[file_id]
    public_count = len(file_state.public_blocks)
    private_count = len(file_state.block_ids) - public_count
    trace.event(
        f"retrieve:{label}:request",
        {
            "file_id": file_id,
            "user": user.address,
            "ownership_owner": csp.ownership.get(file_id),
            "block_count": len(file_state.block_ids),
            "public_block_count": public_count,
            "private_block_count": private_count,
        },
    )
    recovered = retrieve_protocol(user, file_id, csp, engine, user.UID, user.W)
    retrieved_path = save_retrieved_file(CLIENT_DB, file_id if label == "owner" else f"{file_id}.{label}", recovered)
    matched = recovered == expected_bytes
    trace.event(
        f"retrieve:{label}:client",
        {
            "file_id": file_id,
            "user": user.address,
            "sha256_match": matched,
            "saved_path": str(retrieved_path.relative_to(ROOT)),
        },
    )
    return matched


def _process_file(
    trace: TraceLogger,
    source_path: Path,
    owner: UserState,
    buyer: UserState,
    csp: CSPState,
    chain: Any,
    engine: CryptoEngine,
    upload_only: bool,
    challenge_blocks: int,
) -> dict[str, Any]:
    file_bytes = source_path.read_bytes()
    before = _database_counts(csp)
    preflight = _preflight_upload(source_path, file_bytes, csp, engine, owner)
    trace.event("upload:request", preflight)
    trace.event(
        "upload:identity",
        {
            "source_file": preflight["source_file"],
            "owner": owner.address,
            "uid": owner.uid,
            "expected_check": "CSP verifies e(UID,g)==e(H4(uid)*t,W) during protocol execution",
            "t_preview": preflight["t_preview"],
        },
    )
    trace.event(
        "dedup:file",
        {
            "source_file": preflight["source_file"],
            "predicted_duplicate": preflight["duplicate_file_predicted"],
            "existing_file_id": preflight["duplicate_file_id_predicted"],
        },
    )
    trace.event(
        "dedup:block",
        {
            "source_file": preflight["source_file"],
            "total": preflight["block_count"],
            "duplicate": preflight["duplicate_block_count_predicted"],
            "new": preflight["new_block_count_predicted"],
            "duplicate_indices_preview": preflight["duplicate_indices_preview"],
            "new_indices_preview": preflight["new_indices_preview"],
        },
    )

    upload = upload_and_dedup_protocol(
        owner,
        file_bytes,
        csp,
        chain,
        engine,
        public_block_indices=preflight["public_blocks"],
    )
    file_state = csp.files[upload["file_id"]]
    chain_upload_record = chain.uploads.get(upload["file_id"], {})
    after = _database_counts(csp)
    save_upload_record(CLIENT_DB, owner, source_path, upload, file_state, chain_upload_record)

    trace.event(
        "upload:payload",
        {
            "source_file": preflight["source_file"],
            "file_id": upload["file_id"],
            "encrypted_block_count": len(file_state.block_ids),
            "tag_count": len(file_state.block_tags),
            "key_cipher_blocks_for_owner": sum(1 for item in csp.key_ciphers.values() if owner.address in item),
            "duplicate_file": bool(upload.get("duplicate_file", False)),
            "duplicate_file_id": upload.get("duplicate_file_id"),
            "duplicate_block_count": upload.get("duplicate_block_count", 0),
            "new_block_count": upload.get("new_block_count", 0),
        },
    )
    trace.event(
        "csp:store",
        {
            "source_file": preflight["source_file"],
            "file_id": upload["file_id"],
            "before": before,
            "after": after,
            "delta_files": after["files"] - before["files"],
            "delta_blocks": after["blocks"] - before["blocks"],
            "delta_authenticators": after["authenticators"] - before["authenticators"],
        },
    )
    trace.event(
        "hvt",
        {
            "source_file": preflight["source_file"],
            "file_id": upload["file_id"],
            "root": file_state.mht_root,
            **_tree_stats(file_state.metadata.get("tree")),
        },
    )
    trace.event(
        "chain:upload",
        {
            "source_file": preflight["source_file"],
            "file_id": upload["file_id"],
            "contract_address": chain.contract_address,
            "record": chain_upload_record,
        },
    )

    audit_ok = None
    owner_retrieve_ok = None
    transfer_ok = None
    buyer_retrieve_ok = None
    gas_used = _chain_gas(chain_upload_record)
    if not upload_only:
        audit_ok, audit_gas = _run_audit(trace, upload["file_id"], file_state, csp, chain, engine, owner, challenge_blocks)
        gas_used += audit_gas
        owner_retrieve_ok = _run_retrieve(trace, "owner", owner, upload["file_id"], file_bytes, csp, engine)
        trace.event(
            "transfer:request",
            {
                "file_id": upload["file_id"],
                "from_owner": owner.address,
                "to_owner": buyer.address,
                "description": "buyer requests transfer; old owner accessibility is checked before CSP rewraps private block keys",
            },
        )
        transfer = ownership_transfer_protocol(owner, buyer, upload["file_id"], csp, chain, engine)
        gas_used += _chain_gas(chain.transfers.get(upload["file_id"], {}))
        transfer_ok = bool(transfer["success"])
        save_upload_record(CLIENT_DB, buyer, source_path, upload, csp.files[upload["file_id"]], chain_upload_record)
        trace.event(
            "transfer:csp",
            {
                "file_id": upload["file_id"],
                "success": transfer_ok,
                "old_owner": transfer["old_owner"],
                "new_owner": transfer["new_owner"],
                "ownership_owner": csp.ownership.get(upload["file_id"]),
                "transfer_record": chain.transfers.get(upload["file_id"], {}),
            },
        )
        buyer_retrieve_ok = _run_retrieve(trace, "buyer", buyer, upload["file_id"], file_bytes, csp, engine)

    return {
        "source_file": preflight["source_file"],
        "file_id": upload["file_id"],
        "block_count": len(file_state.block_ids),
        "duplicate_file": bool(upload.get("duplicate_file", False)),
        "duplicate_block_count": int(upload.get("duplicate_block_count", 0)),
        "new_block_count": int(upload.get("new_block_count", 0)),
        "audit_ok": audit_ok,
        "owner_retrieve_ok": owner_retrieve_ok,
        "transfer_ok": transfer_ok,
        "buyer_retrieve_ok": buyer_retrieve_ok,
        "gas_used": gas_used,
    }


def _count_true(rows: Iterable[dict[str, Any]], key: str) -> int:
    return sum(1 for row in rows if row.get(key) is True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Batch real-file full flow with detailed Client/CSP/contract traces.")
    parser.add_argument("--pattern", default="*.bin", help="Glob under data/client_files. Default uploads generated experiment *.bin files.")
    parser.add_argument("--limit", type=int, default=None, help="Only process the first N files.")
    parser.add_argument("--fresh", action="store_true", help="Reset data/client_db and data/csp_db before running.")
    parser.add_argument("--upload-only", action="store_true", help="Run upload/dedup/HVT/chain record only.")
    parser.add_argument("--challenge-blocks", type=int, default=2, help="Audit challenge size per file.")
    args = parser.parse_args()

    load_environment()
    if args.fresh:
        reset_client_db(CLIENT_DB)
        reset_csp_db(CSP_DB)

    trace = TraceLogger(RESULTS_DIR)
    try:
        owner = _build_user("USER1_ADDRESS", "USER1_PRIVATE_KEY", "client-owner")
        buyer = _build_user("USER2_ADDRESS", "USER2_PRIVATE_KEY", "client-buyer")
        engine = CryptoEngine(setup(sectors_per_block=128, s=b"real-file-full-flow"))
        chain = deploy_contract(
            connect_chain(chain_id=int(os.getenv("GANACHE_CHAIN_ID", "1337")), require_real=True),
            str(ROOT / "contracts" / "AuditSystem.sol"),
        )
        csp = load_csp_state(CSP_DB, _env("CSP_ADDRESS"), _env("CSP_PRIVATE_KEY"), storage_capacity=10**12)
        repaired = _repair_authenticators_if_needed(csp, engine)
        save_user_profile(CLIENT_DB, owner)
        save_user_profile(CLIENT_DB, buyer)

        files = _candidate_files(args.pattern, args.limit)
        if not files:
            raise FileNotFoundError(f"No client files matched pattern {args.pattern!r} under {CLIENT_FILES}")
        trace.event(
            "run:start",
            {
                "file_count": len(files),
                "pattern": args.pattern,
                "fresh": args.fresh,
                "upload_only": args.upload_only,
                "chain_backend": chain.backend,
                "contract_address": chain.contract_address,
                "client_db": str(CLIENT_DB.relative_to(ROOT)),
                "csp_db": str(CSP_DB.relative_to(ROOT)),
                "repaired_authenticators": repaired,
                "initial_csp_counts": _database_counts(csp),
            },
        )

        rows = []
        for index, source_path in enumerate(files, start=1):
            trace.event("file:start", {"index": index, "total": len(files), "source_file": str(source_path.relative_to(ROOT))})
            rows.append(
                _process_file(
                    trace,
                    source_path,
                    owner,
                    buyer,
                    csp,
                    chain,
                    engine,
                    upload_only=args.upload_only,
                    challenge_blocks=args.challenge_blocks,
                )
            )
            save_csp_state(csp, CSP_DB, engine.params)
            trace.event("file:end", rows[-1])

        summary = {
            "processed_files": len(rows),
            "duplicate_files": sum(1 for row in rows if row["duplicate_file"]),
            "total_blocks": sum(row["block_count"] for row in rows),
            "duplicate_blocks": sum(row["duplicate_block_count"] for row in rows),
            "new_blocks": sum(row["new_block_count"] for row in rows),
            "audit_success": _count_true(rows, "audit_ok"),
            "owner_retrieve_success": _count_true(rows, "owner_retrieve_ok"),
            "transfer_success": _count_true(rows, "transfer_ok"),
            "buyer_retrieve_success": _count_true(rows, "buyer_retrieve_ok"),
            "total_gas_used": sum(row["gas_used"] for row in rows),
            "final_csp_counts": _database_counts(csp),
            "events_path": str(trace.events_path.relative_to(ROOT)),
            "summary_path": str(trace.summary_path.relative_to(ROOT)),
        }
        save_csp_state(csp, CSP_DB, engine.params)
        trace.summary(summary)
    finally:
        trace.close()


if __name__ == "__main__":
    main()
