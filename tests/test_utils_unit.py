from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.utils import (
    ConfigLoader,
    compressed_public_key_from_private,
    deserialize_bytes_list,
    serialize_bytes_list,
    serialize_json,
    sha256_hex,
    split_file_into_blocks_and_sectors,
)


def test_sha256_hex_matches_hashlib():
    data = b"dup-mix-utils"
    assert sha256_hex(data) == hashlib.sha256(data).hexdigest()


def test_serialize_deserialize_bytes_list_roundtrip():
    items = [b"\x00\x01", b"abc", b"\xff" * 4]
    encoded = serialize_bytes_list(items)
    decoded = deserialize_bytes_list(encoded)
    assert decoded == items


def test_serialize_json_is_stable_sorted():
    payload = {"b": 2, "a": 1}
    assert serialize_json(payload) == b'{"a": 1, "b": 2}'


def test_split_file_requires_input():
    with pytest.raises(ValueError):
        split_file_into_blocks_and_sectors(file_path=None, data=None)


def test_split_file_missing_path_raises(tmp_path: Path):
    missing = tmp_path / "missing.bin"
    with pytest.raises(FileNotFoundError):
        split_file_into_blocks_and_sectors(file_path=str(missing))


def test_split_empty_data_returns_single_zero_block():
    blocks = split_file_into_blocks_and_sectors(data=b"", block_size=16, sectors_per_block=4)
    assert len(blocks) == 1
    assert b"".join(blocks[0]) == b"\x00" * 16


def test_config_loader_env_has_priority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    config_path = tmp_path / "config.yaml"
    env_path = tmp_path / ".env"
    config_path.write_text("APP_TEST_KEY: yaml-value\n", encoding="utf-8")
    env_path.write_text("APP_TEST_KEY=env-value\n", encoding="utf-8")
    monkeypatch.delenv("APP_TEST_KEY", raising=False)

    loader = ConfigLoader(config_path=str(config_path), env_path=str(env_path))
    assert loader.get("APP_TEST_KEY") == "env-value"
    assert loader.get("NOT_EXIST_KEY", "fallback") == "fallback"


def test_compressed_public_key_from_private_shape():
    private_key = "0x" + "11" * 32
    pub = compressed_public_key_from_private(private_key)
    assert len(pub) == 66
    assert pub[:2] in {"02", "03"}
