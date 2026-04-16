from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.mht import build_improved_mht, delete_block_mht, insert_block_mht, modify_block_mht
from src.utils import bytes_to_int, ensure_bytes, flatten_blocks, int_to_bytes, split_file_into_blocks_and_sectors


def test_mht_empty_and_updates():
    tree, root = build_improved_mht([])
    assert tree["tags"] == []
    assert tree["root"] == root
    assert len(root) == 64

    base, root_base = build_improved_mht(["a", "b", "c"])
    inserted, root_inserted = insert_block_mht(base, "x", 1)
    modified, root_modified = modify_block_mht(inserted, 0, "z")
    deleted, root_deleted = delete_block_mht(modified, 2)

    assert root_base != root_inserted
    assert root_inserted != root_modified
    assert root_modified != root_deleted
    assert deleted["tags"] == ["z", "x", "c"]


def test_split_blocks_padding_and_flatten():
    block_size = 16
    sectors_per_block = 4
    data = b"abc" * 10  # 30 bytes -> 2 blocks after padding

    blocks = split_file_into_blocks_and_sectors(
        data=data,
        block_size=block_size,
        sectors_per_block=sectors_per_block,
    )

    assert len(blocks) == 2
    assert all(len(block) == sectors_per_block for block in blocks)
    flattened = flatten_blocks(blocks)
    assert len(flattened) == block_size * 2
    assert flattened[: len(data)] == data
    assert flattened[len(data) :] == b"\x00" * (len(flattened) - len(data))


def test_ensure_bytes_and_int_roundtrip():
    assert ensure_bytes("abc") == b"abc"
    assert ensure_bytes(258) == b"\x01\x02"
    assert ensure_bytes(b"\x01\xff") == b"\x01\xff"

    value = 123456789
    encoded = int_to_bytes(value)
    assert bytes_to_int(encoded) == value
