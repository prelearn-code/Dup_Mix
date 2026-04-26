from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .models import CSPState, FileState, GlobalParams


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8")


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _file_to_json(file_state: FileState) -> Dict[str, Any]:
    return {
        "file_id": file_state.file_id,
        "owner_address": file_state.owner_address,
        "file_size": file_state.file_size,
        "file_hash": file_state.file_hash,
        "t": file_state.t,
        "block_ids": file_state.block_ids,
        "block_tags": file_state.block_tags,
        "public_blocks": sorted(file_state.public_blocks),
        "is_deduplicated": file_state.is_deduplicated,
        "mht_root": file_state.mht_root,
        "metadata": file_state.metadata,
    }


def _file_from_json(payload: Dict[str, Any]) -> FileState:
    return FileState(
        file_id=payload["file_id"],
        owner_address=payload["owner_address"],
        file_size=int(payload["file_size"]),
        file_hash=payload["file_hash"],
        t=payload["t"],
        block_ids=list(payload["block_ids"]),
        block_tags=list(payload["block_tags"]),
        public_blocks=set(payload.get("public_blocks", [])),
        is_deduplicated=bool(payload.get("is_deduplicated", False)),
        mht_root=payload.get("mht_root", ""),
        metadata=dict(payload.get("metadata", {})),
    )


def _block_meta(block: Dict[str, Any], sectors: List[bytes]) -> Dict[str, Any]:
    return {
        "tag": block["tag"],
        "sector_lengths": [len(sector) for sector in sectors],
        "sector_values": list(block.get("sector_values", [])),
        "is_public": bool(block.get("is_public", False)),
        "owners": sorted(block.get("owners", [])),
        "sector_keys": list(block.get("sector_keys", [])),
    }


def _split_blob(blob: bytes, lengths: Iterable[int]) -> List[bytes]:
    sectors: List[bytes] = []
    offset = 0
    for length in lengths:
        end = offset + int(length)
        sectors.append(blob[offset:end])
        offset = end
    if offset != len(blob):
        raise ValueError("Stored sector lengths do not match sectors.bin size.")
    return sectors


def reset_csp_db(db_path: str | Path) -> None:
    path = Path(db_path)
    if path.exists():
        shutil.rmtree(path)


def _crypto_params_to_json(params: GlobalParams | None) -> Dict[str, Any]:
    if params is None:
        return {}
    return {
        "s_param": params.s_param.hex(),
        "group_order": params.group_order,
        "generator": params.generator,
        "r_values": params.r_values,
        "sectors_per_block": params.sectors_per_block,
        "pairing_backend": params.pairing_backend,
    }


def save_csp_state(csp_state: CSPState, db_path: str | Path, params: GlobalParams | None = None) -> None:
    root = Path(db_path)
    root.mkdir(parents=True, exist_ok=True)
    _write_json(
        root / "manifest.json",
        {
            "schema": "dupmix-csp-db-v1",
            "address": csp_state.address,
            "storage_capacity": csp_state.storage_capacity,
            "used_capacity": csp_state.used_capacity,
            "crypto_params": _crypto_params_to_json(params),
        },
    )
    _write_json(root / "indexes" / "file_index.json", csp_state.file_index)
    _write_json(root / "indexes" / "block_index.json", csp_state.block_index)
    _write_json(root / "indexes" / "ownership.json", csp_state.ownership)
    _write_json(root / "audit_history.json", csp_state.audit_history)

    for file_id, file_state in csp_state.files.items():
        _write_json(root / "files" / f"{file_id}.json", _file_to_json(file_state))

    for block_id, block in csp_state.blocks.items():
        sectors = [bytes(sector) for sector in block.get("sectors", [])]
        block_dir = root / "blocks" / block_id
        _write_json(block_dir / "meta.json", _block_meta(block, sectors))
        block_dir.mkdir(parents=True, exist_ok=True)
        (block_dir / "sectors.bin").write_bytes(b"".join(sectors))

    for block_id, auth in csp_state.authenticators.items():
        _write_json(root / "authenticators" / f"{block_id}.json", auth)

    for block_id, owner_map in csp_state.key_ciphers.items():
        for owner, key_cipher in owner_map.items():
            path = root / "key_ciphers" / block_id / f"{owner}.bin"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(bytes(key_cipher))


def load_csp_state(
    db_path: str | Path,
    address: str,
    private_key: str,
    storage_capacity: int,
) -> CSPState:
    root = Path(db_path)
    manifest = _read_json(root / "manifest.json", {})
    csp = CSPState(
        address=manifest.get("address", address),
        private_key=private_key,
        storage_capacity=int(manifest.get("storage_capacity", storage_capacity)),
        used_capacity=int(manifest.get("used_capacity", 0)),
    )
    if not root.exists():
        return csp

    csp.file_index = _read_json(root / "indexes" / "file_index.json", {})
    csp.block_index = _read_json(root / "indexes" / "block_index.json", {})
    csp.ownership = _read_json(root / "indexes" / "ownership.json", {})
    csp.audit_history = _read_json(root / "audit_history.json", [])

    for file_path in sorted((root / "files").glob("*.json")):
        file_state = _file_from_json(_read_json(file_path, {}))
        csp.files[file_state.file_id] = file_state

    for block_dir in sorted((root / "blocks").glob("*")):
        if not block_dir.is_dir():
            continue
        meta = _read_json(block_dir / "meta.json", {})
        sectors = _split_blob((block_dir / "sectors.bin").read_bytes(), meta.get("sector_lengths", []))
        csp.blocks[block_dir.name] = {
            "tag": meta["tag"],
            "sectors": sectors,
            "sector_values": list(meta.get("sector_values", [])),
            "is_public": bool(meta.get("is_public", False)),
            "owners": set(meta.get("owners", [])),
            "sector_keys": list(meta.get("sector_keys", [])),
        }

    for auth_path in sorted((root / "authenticators").glob("*.json")):
        csp.authenticators[auth_path.stem] = _read_json(auth_path, {})

    for block_dir in sorted((root / "key_ciphers").glob("*")):
        if not block_dir.is_dir():
            continue
        owner_map: Dict[str, bytes] = {}
        for key_path in sorted(block_dir.glob("*.bin")):
            owner_map[key_path.stem] = key_path.read_bytes()
        if owner_map:
            csp.key_ciphers[block_dir.name] = owner_map

    return csp
