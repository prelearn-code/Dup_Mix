from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.models import CSPState, FileState
from src.storage import (
    block_level_dedup_check,
    file_level_dedup_check,
    store_authenticator,
    store_key_cipher,
    store_upload_metadata,
    update_ownership_record,
)


def _build_csp() -> CSPState:
    return CSPState(
        address="0xcsp",
        private_key="0x" + "22" * 32,
        storage_capacity=10**9,
    )


def _build_file(owner: str = "0xowner", t_hex: str = "t-001", file_id: str = "file-001") -> FileState:
    return FileState(
        file_id=file_id,
        owner_address=owner,
        file_size=12,
        file_hash="hash-001",
        t=t_hex,
        block_ids=["blk-1", "blk-2"],
        block_tags=["tag-1", "tag-2"],
    )


def test_file_level_dedup_check_changes_after_store():
    csp = _build_csp()
    file_state = _build_file(t_hex="t-dup")

    assert not file_level_dedup_check(csp, "t-dup")
    store_upload_metadata(csp, file_state)
    assert file_level_dedup_check(csp, "t-dup")


def test_block_level_dedup_check_returns_missing_indices():
    csp = _build_csp()
    csp.block_index["tag-exist-a"] = "blk-a"
    csp.block_index["tag-exist-b"] = "blk-b"

    tags = ["tag-exist-a", "tag-new", "tag-exist-b", "tag-another-new"]
    missing = block_level_dedup_check(csp, tags)

    assert missing == [1, 3]


def test_store_upload_metadata_writes_all_indexes():
    csp = _build_csp()
    file_state = _build_file(owner="0xalice", t_hex="t-meta", file_id="file-meta")

    store_upload_metadata(csp, file_state)

    assert csp.files["file-meta"] is file_state
    assert csp.file_index["t-meta"] == "file-meta"
    assert csp.ownership["file-meta"] == "0xalice"


def test_store_authenticator_and_key_cipher():
    csp = _build_csp()

    store_authenticator(csp, "blk-99", sigma=123, y_value=456, y_group=789)
    assert csp.authenticators["blk-99"] == {"sigma": 123, "y": 456, "Y": 789}

    store_key_cipher(csp, "blk-99", "0xalice", b"k1")
    store_key_cipher(csp, "blk-99", "0xbob", b"k2")
    assert csp.key_ciphers["blk-99"]["0xalice"] == b"k1"
    assert csp.key_ciphers["blk-99"]["0xbob"] == b"k2"


def test_update_ownership_record_updates_both_maps():
    csp = _build_csp()
    file_state = _build_file(owner="0xold", file_id="file-own", t_hex="t-own")
    store_upload_metadata(csp, file_state)

    update_ownership_record(csp, "file-own", "0xnew")

    assert csp.ownership["file-own"] == "0xnew"
    assert csp.files["file-own"].owner_address == "0xnew"
