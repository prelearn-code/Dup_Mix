from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Dict

from .models import FileState, UserState


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8")


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def reset_client_db(db_path: str | Path) -> None:
    path = Path(db_path)
    if path.exists():
        shutil.rmtree(path)


def save_user_profile(db_path: str | Path, user: UserState) -> None:
    root = Path(db_path)
    _write_json(
        root / "users" / f"{user.address}.json",
        {
            "address": user.address,
            "uid": user.uid,
            "public_key": user.public_key,
            "private_key_source": ".env",
        },
    )


def save_upload_record(
    db_path: str | Path,
    user: UserState,
    source_path: str | Path,
    upload: Dict[str, Any],
    file_state: FileState,
    chain_upload_record: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    root = Path(db_path)
    local = user.local_files.get(file_state.file_id, {})
    record = {
        "file_id": file_state.file_id,
        "owner_address": user.address,
        "uid": user.uid,
        "source_path": str(source_path),
        "file_size": file_state.file_size,
        "file_hash": file_state.file_hash,
        "t": file_state.t,
        "root": file_state.mht_root,
        "block_ids": file_state.block_ids,
        "block_tags": file_state.block_tags,
        "public_blocks": sorted(file_state.public_blocks),
        "duplicate_file": bool(upload.get("duplicate_file", False)),
        "mu": user.mu,
        "UID": user.UID.hex(),
        "W": user.W.hex(),
        "fk": local.get("fk"),
        "gamma": local.get("gamma"),
        "sector_keys": local.get("sector_keys", []),
        "chain_upload_record": chain_upload_record or {},
    }
    _write_json(root / "uploads" / f"{file_state.file_id}.json", record)
    return record


def load_upload_record(db_path: str | Path, file_id: str) -> Dict[str, Any]:
    return _read_json(Path(db_path) / "uploads" / f"{file_id}.json")


def save_retrieved_file(db_path: str | Path, file_id: str, payload: bytes) -> Path:
    path = Path(db_path) / "retrieved" / f"{file_id}.bin"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path
