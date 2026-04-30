from __future__ import annotations

import base64
import json
import os
import shutil
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.chain import connect_chain, deploy_contract
from src.crypto import CryptoEngine, setup
from src.local_client_store import save_retrieved_file, save_upload_record, save_user_profile
from src.local_csp_store import load_csp_state, reset_csp_db, save_csp_state
from src.models import CSPState, UserState
from src.protocol import (
    audit_req,
    delete_protocol,
    insert_protocol,
    modify_protocol,
    ownership_transfer_protocol,
    proof_gen,
    retrieve_protocol,
    upload_and_dedup_protocol,
    verify_proof_protocol,
)
from src.utils import compressed_public_key_from_private, load_environment, sha256_hex, split_file_into_blocks_and_sectors


CLIENT_FILES = ROOT / "data" / "client_files"
CLIENT_DB = ROOT / "data" / "client_db"
CSP_DB = ROOT / "data" / "csp_db"
RESULTS_DIR = ROOT / "results" / "demo_console"
EVENTS_PATH = RESULTS_DIR / "events.jsonl"


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


def _preview(value: str | bytes | int | None, size: int = 18) -> str:
    if value is None:
        return ""
    if isinstance(value, int):
        value = f"{value:064x}"
    if isinstance(value, bytes):
        value = value.hex()
    return str(value)[:size]


def _json_default(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, Path):
        return str(value)
    return str(value)


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True, default=_json_default), encoding="utf-8")


def _read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return {} if default is None else default
    return json.loads(path.read_text(encoding="utf-8"))


def _tree_stats(tree: Any) -> dict[str, int]:
    if not isinstance(tree, dict):
        return {"nodes": 0, "height": 0, "leaves": 0}
    levels = tree.get("levels")
    if isinstance(levels, list):
        return {"nodes": sum(len(level) for level in levels if isinstance(level, list)), "height": len(levels), "leaves": len(levels[0]) if levels else 0}
    tags = tree.get("tags", [])
    return {"nodes": 0, "height": 0, "leaves": len(tags) if isinstance(tags, list) else 0}


def _summarize_audit_history(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary = []
    for row in rows[-20:]:
        challenge = row.get("challenge", {})
        proof = row.get("proof", {})
        chain_result = row.get("chain_result", {})
        summary.append(
            {
                "challenge_id": challenge.get("challenge_id"),
                "z": challenge.get("z"),
                "indices": proof.get("indices", [])[:12],
                "coeff_count": len(proof.get("coeffs", [])),
                "P_count": len(proof.get("P", [])),
                "sigma_c": _preview(proof.get("sigma_c"), 24),
                "proof_digest_hex": proof.get("proof_digest_hex"),
                "valid": row.get("valid"),
                "chain_result": chain_result,
            }
        )
    return summary


def _client_file_rows() -> list[dict[str, Any]]:
    CLIENT_FILES.mkdir(parents=True, exist_ok=True)
    rows = []
    for path in sorted(CLIENT_FILES.rglob("*")):
        if not path.is_file() or path.name.startswith(".") or path.name == "manifest.json":
            continue
        rel = path.relative_to(CLIENT_FILES).as_posix()
        rows.append(
            {
                "name": rel,
                "size": path.stat().st_size,
                "sha256": sha256_hex(path.read_bytes()),
                "path": str(path.relative_to(ROOT)),
            }
        )
    return rows


def _safe_client_file(name: str) -> Path:
    if not name:
        raise ValueError("Missing client file name.")
    root = CLIENT_FILES.resolve()
    path = (CLIENT_FILES / name).resolve()
    if root not in path.parents or not path.is_file():
        raise FileNotFoundError(f"Client file not found: {name}")
    return path


def _tree_node(node: dict[str, Any], node_id: str = "root") -> dict[str, Any]:
    item = {
        "id": node_id,
        "h": node.get("h", ""),
        "lN": node.get("lN"),
        "p": node.get("p"),
        "tag": node.get("tag"),
        "kind": "leaf" if "tag" in node else "internal",
    }
    children = []
    if isinstance(node.get("left"), dict):
        children.append(_tree_node(node["left"], f"{node_id}.L"))
    if isinstance(node.get("right"), dict):
        children.append(_tree_node(node["right"], f"{node_id}.R"))
    if children:
        item["children"] = children
    return item


class DemoRuntime:
    def __init__(self) -> None:
        load_environment()
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.engine = CryptoEngine(setup(sectors_per_block=128, s=b"real-file-full-flow"))
        self.owner = _build_user("USER1_ADDRESS", "USER1_PRIVATE_KEY", "client-owner")
        self.buyer = _build_user("USER2_ADDRESS", "USER2_PRIVATE_KEY", "client-buyer")
        self.chain = deploy_contract(
            connect_chain(chain_id=int(os.getenv("GANACHE_CHAIN_ID", "1337")), require_real=True),
            str(ROOT / "contracts" / "AuditSystem.sol"),
        )
        self.csp = load_csp_state(CSP_DB, _env("CSP_ADDRESS"), _env("CSP_PRIVATE_KEY"), storage_capacity=10**12)
        self._ensure_profiles()
        self._event("run:start", {"chain_backend": self.chain.backend, "contract_address": self.chain.contract_address})

    def _ensure_profiles(self) -> None:
        save_user_profile(CLIENT_DB, self.owner)
        save_user_profile(CLIENT_DB, self.buyer)
        save_csp_state(self.csp, CSP_DB, self.engine.params)

    def _event(self, stage: str, payload: dict[str, Any]) -> None:
        row = {"time": datetime.now(timezone.utc).isoformat(), "stage": stage, **payload}
        EVENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with EVENTS_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, default=_json_default) + "\n")

    def reset(self) -> dict[str, Any]:
        with self.lock:
            if CLIENT_DB.exists():
                shutil.rmtree(CLIENT_DB)
            reset_csp_db(CSP_DB)
            if EVENTS_PATH.exists():
                EVENTS_PATH.unlink()
            self.csp = CSPState(address=_env("CSP_ADDRESS"), private_key=_env("CSP_PRIVATE_KEY"), storage_capacity=10**12)
            self._ensure_profiles()
            self._event("demo:reset", {"client_db": str(CLIENT_DB.relative_to(ROOT)), "csp_db": str(CSP_DB.relative_to(ROOT))})
            return self.state()

    def preflight(self, file_name: str, file_bytes: bytes) -> dict[str, Any]:
        blocks = split_file_into_blocks_and_sectors(
            data=file_bytes,
            block_size=self.engine.params.block_size,
            sectors_per_block=self.engine.params.sectors_per_block,
        )
        public_blocks = [0] if blocks else []
        fk, sector_keys = self.engine.keygen(file_bytes, blocks)
        encrypted_blocks, key_cipher_map = self.engine.encrypt_blocks(
            blocks,
            sector_keys,
            public_blocks,
            bytes.fromhex(self.owner.public_key[2:] if self.owner.public_key.startswith("0x") else self.owner.public_key),
        )
        t, tags = self.engine.taggen(encrypted_blocks, fk)
        tag_hexes = [f"{tag:064x}" for tag in tags]
        seen_new: set[str] = set()
        duplicate_indices = []
        new_indices = []
        for index, tag in enumerate(tag_hexes):
            if tag in self.csp.block_index or tag in seen_new:
                duplicate_indices.append(index)
            else:
                new_indices.append(index)
                seen_new.add(tag)
        return {
            "file_name": file_name,
            "file_size": len(file_bytes),
            "file_hash": sha256_hex(file_bytes),
            "block_count": len(blocks),
            "public_blocks": public_blocks,
            "private_block_count": max(0, len(blocks) - len(public_blocks)),
            "t": f"{t:064x}",
            "t_preview": _preview(t),
            "tag_count": len(tag_hexes),
            "tag_previews": [_preview(tag) for tag in tag_hexes[:8]],
            "key_cipher_count": len(key_cipher_map),
            "duplicate_file": f"{t:064x}" in self.csp.file_index,
            "duplicate_file_id": self.csp.file_index.get(f"{t:064x}"),
            "duplicate_block_count": len(duplicate_indices),
            "new_block_count": len(new_indices),
            "duplicate_indices_preview": duplicate_indices[:20],
            "new_indices_preview": new_indices[:20],
        }

    def upload(self, file_name: str, file_bytes: bytes) -> dict[str, Any]:
        with self.lock:
            CLIENT_FILES.mkdir(parents=True, exist_ok=True)
            source_path = CLIENT_FILES / file_name
            source_path.write_bytes(file_bytes)
            preflight = self.preflight(file_name, file_bytes)
            self._event("upload:request", preflight)
            upload = upload_and_dedup_protocol(
                self.owner,
                file_bytes,
                self.csp,
                self.chain,
                self.engine,
                public_block_indices=preflight["public_blocks"],
            )
            file_state = self.csp.files[upload["file_id"]]
            chain_record = self.chain.uploads.get(upload["file_id"], {})
            save_upload_record(CLIENT_DB, self.owner, source_path, upload, file_state, chain_record)
            save_csp_state(self.csp, CSP_DB, self.engine.params)
            payload = {
                "file_id": upload["file_id"],
                "duplicate_file": bool(upload.get("duplicate_file")),
                "block_count": len(file_state.block_ids),
                "mht_root": file_state.mht_root,
                "chain_record": chain_record,
                "preflight": preflight,
            }
            self._event("upload:payload", payload)
            self._event("csp:store", {"file_id": upload["file_id"], "counts": self._csp_counts()})
            self._event("hvt", {"file_id": upload["file_id"], "root": file_state.mht_root, **_tree_stats(file_state.metadata.get("tree"))})
            self._event("chain:upload", {"file_id": upload["file_id"], "record": chain_record})
            return {"operation": payload, "state": self.state()}

    def upload_client_file(self, name: str) -> dict[str, Any]:
        path = _safe_client_file(name)
        return self.upload(path.name, path.read_bytes())

    def audit(self, file_id: str, z_value: int) -> dict[str, Any]:
        with self.lock:
            file_state = self.csp.files[file_id]
            challenge = audit_req(file_id, len(file_state.block_ids), self.engine, chain_state=self.chain, requester=self.owner.address, z_value=z_value)
            proof = proof_gen(challenge, file_state, self.csp, self.engine)
            verified = verify_proof_protocol(proof, challenge, file_state, self.csp, self.chain, self.engine)
            save_csp_state(self.csp, CSP_DB, self.engine.params)
            payload = {
                "file_id": file_id,
                "challenge_id": challenge["challenge_id"],
                "z": challenge["z"],
                "indices": proof["indices"],
                "sigma_c_preview": _preview(proof["sigma_c"]),
                "proof_digest": proof["proof_digest_hex"],
                "verified": verified,
                "chain_challenge": self.chain.challenges.get(challenge["challenge_id"], {}),
                "chain_result": self.chain.proof_results.get(challenge["challenge_id"], {}),
            }
            self._event("audit:verify", payload)
            return {"operation": payload, "state": self.state()}

    def update_file(self, file_id: str, op: str, index: int | None, payload_text: str) -> dict[str, Any]:
        with self.lock:
            before = self.csp.files[file_id].mht_root
            data = payload_text.encode() or b"demo-update-block"
            if op == "insert":
                result = insert_protocol(self.owner, file_id, data, self.csp, self.chain, self.engine, index=index, is_public=False)
            elif op == "modify":
                result = modify_protocol(self.owner, file_id, int(index or 0), data, self.csp, self.chain, self.engine, is_public=False)
            elif op == "delete":
                result = delete_protocol(self.owner, file_id, int(index or 0), self.csp, self.chain, self.engine)
            else:
                raise ValueError("Unsupported update op.")
            save_upload_record(CLIENT_DB, self.owner, CLIENT_FILES / f"{file_id}.updated", {"duplicate_file": False}, self.csp.files[file_id], self.chain.uploads.get(file_id, {}))
            save_csp_state(self.csp, CSP_DB, self.engine.params)
            after = self.csp.files[file_id].mht_root
            chain_update = result.get("chain_update", {"file_id": file_id, "root": after, "op_type": op})
            payload = {"file_id": file_id, "op": op, "index": index, "old_root": before, "new_root": after, "result": result, "chain_update": chain_update}
            self._event("update:commit", payload)
            return {"operation": payload, "state": self.state()}

    def retrieve(self, file_id: str, role: str) -> dict[str, Any]:
        with self.lock:
            user = self.buyer if role == "buyer" else self.owner
            data = retrieve_protocol(user, file_id, self.csp, self.engine, user.UID, user.W)
            path = save_retrieved_file(CLIENT_DB, file_id if role == "owner" else f"{file_id}.{role}", data)
            file_hash = sha256_hex(data)
            payload = {"file_id": file_id, "role": role, "size": len(data), "sha256": file_hash, "saved_path": str(path.relative_to(ROOT))}
            self._event(f"retrieve:{role}:client", payload)
            return {"operation": payload, "state": self.state()}

    def transfer(self, file_id: str) -> dict[str, Any]:
        with self.lock:
            result = ownership_transfer_protocol(self.owner, self.buyer, file_id, self.csp, self.chain, self.engine)
            save_upload_record(CLIENT_DB, self.buyer, CLIENT_FILES / f"{file_id}.transfer", {"duplicate_file": False}, self.csp.files[file_id], self.chain.uploads.get(file_id, {}))
            save_csp_state(self.csp, CSP_DB, self.engine.params)
            payload = {"file_id": file_id, **result, "transfer_record": self.chain.transfers.get(file_id, {})}
            self._event("transfer:csp", payload)
            return {"operation": payload, "state": self.state()}

    def _csp_counts(self) -> dict[str, int]:
        return {
            "files": len(self.csp.files),
            "blocks": len(self.csp.blocks),
            "file_index": len(self.csp.file_index),
            "block_index": len(self.csp.block_index),
            "authenticators": len(self.csp.authenticators),
            "key_cipher_blocks": len(self.csp.key_ciphers),
        }

    def _client_state(self) -> dict[str, Any]:
        uploads = []
        for path in sorted((CLIENT_DB / "uploads").glob("*.json"))[-24:]:
            row = _read_json(path)
            uploads.append(
                {
                    "file_id": row.get("file_id"),
                    "owner_address": row.get("owner_address"),
                    "uid": row.get("uid"),
                    "source_path": row.get("source_path"),
                    "file_size": row.get("file_size"),
                    "file_hash": row.get("file_hash"),
                    "t": row.get("t"),
                    "root": row.get("root"),
                    "public_blocks": row.get("public_blocks", []),
                    "duplicate_file": row.get("duplicate_file", False),
                    "mu": row.get("mu"),
                    "UID": row.get("UID"),
                    "W": row.get("W"),
                    "fk": row.get("fk"),
                    "gamma": row.get("gamma"),
                    "block_count": len(row.get("block_ids", [])),
                    "block_ids": row.get("block_ids", [])[:20],
                    "block_tags": row.get("block_tags", [])[:20],
                    "sector_key_count": sum(len(item) for item in row.get("sector_keys", []) if isinstance(item, list)),
                    "chain_upload_record": row.get("chain_upload_record", {}),
                }
            )
        users = [_read_json(path) for path in sorted((CLIENT_DB / "users").glob("*.json"))]
        retrieved = [{"name": path.name, "size": path.stat().st_size, "sha256": sha256_hex(path.read_bytes())} for path in sorted((CLIENT_DB / "retrieved").glob("*.bin"))]
        return {"files": _client_file_rows(), "users": users, "uploads": uploads, "retrieved": retrieved}

    def _csp_state(self) -> dict[str, Any]:
        files = []
        for file_state in sorted(self.csp.files.values(), key=lambda item: item.file_id):
            files.append(
                {
                    "file_id": file_state.file_id,
                    "owner_address": file_state.owner_address,
                    "file_size": file_state.file_size,
                    "file_hash": file_state.file_hash,
                    "t": file_state.t,
                    "mht_root": file_state.mht_root,
                    "block_count": len(file_state.block_ids),
                    "public_blocks": sorted(file_state.public_blocks),
                    "is_deduplicated": file_state.is_deduplicated,
                    "block_ids": file_state.block_ids[:24],
                    "block_tags": file_state.block_tags[:24],
                    "tree_stats": _tree_stats(file_state.metadata.get("tree")),
                }
            )
        blocks = []
        for block_id, block in sorted(self.csp.blocks.items())[:120]:
            auth = self.csp.authenticators.get(block_id, {})
            key_map = self.csp.key_ciphers.get(block_id, {})
            blocks.append(
                {
                    "block_id": block_id,
                    "tag": block.get("tag"),
                    "is_public": bool(block.get("is_public")),
                    "owners": sorted(block.get("owners", [])),
                    "sector_count": len(block.get("sectors", [])),
                    "sector_values_preview": block.get("sector_values", [])[:3],
                    "authenticator": {"sigma": _preview(auth.get("sigma")), "y": _preview(auth.get("y")), "Y": _preview(auth.get("Y"))},
                    "key_payload_owners": sorted(key_map),
                    "key_payload_sizes": {owner: len(payload) for owner, payload in key_map.items()},
                }
            )
        return {
            "manifest": _read_json(CSP_DB / "manifest.json", {}),
            "counts": self._csp_counts(),
            "file_index": self.csp.file_index,
            "block_index_size": len(self.csp.block_index),
            "ownership": self.csp.ownership,
            "files": files,
            "blocks": blocks,
            "audit_history": _summarize_audit_history(self.csp.audit_history),
        }

    def hvt_state(self, file_id: str) -> dict[str, Any]:
        if file_id not in self.csp.files:
            raise KeyError(f"file_id not found: {file_id}")
        file_state = self.csp.files[file_id]
        tree = file_state.metadata.get("tree", {})
        block_rows = []
        for index, block_id in enumerate(file_state.block_ids):
            block = self.csp.blocks.get(block_id, {})
            auth = self.csp.authenticators.get(block_id, {})
            key_map = self.csp.key_ciphers.get(block_id, {})
            block_rows.append(
                {
                    "index": index,
                    "block_id": block_id,
                    "tag": file_state.block_tags[index] if index < len(file_state.block_tags) else block.get("tag"),
                    "is_public": bool(block.get("is_public")),
                    "owners": sorted(block.get("owners", [])),
                    "sector_count": len(block.get("sectors", [])),
                    "sector_values_preview": block.get("sector_values", [])[:8],
                    "authenticator": {
                        "sigma": auth.get("sigma"),
                        "y": auth.get("y"),
                        "Y": auth.get("Y"),
                    },
                    "key_payload_owners": sorted(key_map),
                    "key_payload_sizes": {owner: len(payload) for owner, payload in key_map.items()},
                }
            )
        root_node = tree.get("node") if isinstance(tree, dict) else None
        return {
            "file": {
                "file_id": file_state.file_id,
                "owner_address": file_state.owner_address,
                "file_size": file_state.file_size,
                "file_hash": file_state.file_hash,
                "t": file_state.t,
                "mht_root": file_state.mht_root,
                "block_count": len(file_state.block_ids),
                "tree_stats": _tree_stats(tree),
            },
            "tree": _tree_node(root_node) if isinstance(root_node, dict) else None,
            "tags": tree.get("tags", []) if isinstance(tree, dict) else [],
            "blocks": block_rows,
        }

    def _chain_state(self) -> dict[str, Any]:
        web3 = self.chain.web3_provider
        status: dict[str, Any] = {
            "backend": self.chain.backend,
            "chain_id": self.chain.chain_id,
            "contract_address": self.chain.contract_address,
            "connected": False,
            "latest_block": None,
            "latest_hash": "",
        }
        blocks = []
        transactions = []
        if web3 is not None and web3.is_connected():
            latest = int(web3.eth.block_number)
            block = web3.eth.get_block(latest, full_transactions=True)
            status.update({"connected": True, "latest_block": latest, "latest_hash": block.hash.hex()})
            for number in range(max(0, latest - 7), latest + 1):
                item = web3.eth.get_block(number, full_transactions=True)
                blocks.append({"number": int(item.number), "hash": item.hash.hex(), "tx_count": len(item.transactions), "timestamp": int(item.timestamp)})
                for tx in item.transactions:
                    if self.chain.contract_address and (tx.to or "").lower() != self.chain.contract_address.lower():
                        continue
                    receipt = web3.eth.get_transaction_receipt(tx.hash)
                    transactions.append({"hash": tx.hash.hex(), "block_number": int(tx.blockNumber), "from": tx["from"], "to": tx.to, "gas_used": int(receipt.gasUsed), "status": int(receipt.status)})
        return {
            "status": status,
            "blocks": blocks[-8:],
            "transactions": transactions[-20:],
            "uploads": self.chain.uploads,
            "challenges": self.chain.challenges,
            "proof_results": self.chain.proof_results,
            "transfers": self.chain.transfers,
        }

    def _timeline(self) -> list[dict[str, Any]]:
        if not EVENTS_PATH.exists():
            return []
        rows = []
        for line in EVENTS_PATH.read_text(encoding="utf-8").splitlines()[-120:]:
            if line.strip():
                rows.append(json.loads(line))
        return rows

    def state(self) -> dict[str, Any]:
        return {
            "client": self._client_state(),
            "csp": self._csp_state(),
            "chain": self._chain_state(),
            "timeline": self._timeline(),
        }


RUNTIME: DemoRuntime | None = None


def runtime() -> DemoRuntime:
    global RUNTIME
    if RUNTIME is None:
        RUNTIME = DemoRuntime()
    return RUNTIME


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[demo-api] {self.address_string()} {fmt % args}")

    def _send(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=_json_default).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_OPTIONS(self) -> None:
        self._send(204, {})

    def do_GET(self) -> None:
        try:
            parsed = urlparse(self.path)
            if parsed.path == "/api/state":
                self._send(200, runtime().state())
            elif parsed.path == "/api/client-files":
                self._send(200, {"files": _client_file_rows()})
            elif parsed.path == "/api/chain":
                self._send(200, runtime()._chain_state())
            else:
                parts = parsed.path.strip("/").split("/")
                if len(parts) == 5 and parts[:3] == ["api", "csp", "files"] and parts[4] == "hvt":
                    self._send(200, runtime().hvt_state(parts[3]))
                    return
                self._send(404, {"error": "not found"})
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def do_POST(self) -> None:
        try:
            parsed = urlparse(self.path)
            payload = self._body()
            rt = runtime()
            if parsed.path == "/api/demo/reset":
                self._send(200, rt.reset())
                return
            if parsed.path == "/api/files/preflight":
                data = base64.b64decode(payload.get("content_base64", ""))
                self._send(200, rt.preflight(payload.get("file_name", "upload.bin"), data))
                return
            if parsed.path == "/api/files/preflight-client-db":
                path = _safe_client_file(payload.get("file_name", ""))
                self._send(200, rt.preflight(path.name, path.read_bytes()))
                return
            if parsed.path == "/api/files/upload":
                data = base64.b64decode(payload.get("content_base64", ""))
                self._send(200, rt.upload(payload.get("file_name", "upload.bin"), data))
                return
            if parsed.path == "/api/files/upload-from-client-db":
                self._send(200, rt.upload_client_file(payload.get("file_name", "")))
                return
            parts = parsed.path.strip("/").split("/")
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "files":
                file_id = parts[2]
                action = parts[3]
                if action == "audit":
                    self._send(200, rt.audit(file_id, int(payload.get("z", 2))))
                elif action == "update":
                    self._send(200, rt.update_file(file_id, payload.get("op", "insert"), payload.get("index"), payload.get("payload", "")))
                elif action == "retrieve":
                    self._send(200, rt.retrieve(file_id, payload.get("role", "owner")))
                elif action == "transfer":
                    self._send(200, rt.transfer(file_id))
                else:
                    self._send(404, {"error": "not found"})
                return
            self._send(404, {"error": "not found"})
        except Exception as exc:
            self._send(500, {"error": str(exc)})


def main() -> None:
    host = os.getenv("DUPMIX_DEMO_HOST", "127.0.0.1")
    port = int(os.getenv("DUPMIX_DEMO_PORT", "8787"))
    _ = runtime()
    print(f"Demo API listening on http://{host}:{port}")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
