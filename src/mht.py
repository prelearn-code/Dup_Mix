from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Sequence, Tuple


def _leaf_hash(tag: str) -> str:
    return hashlib.sha256(f"leaf|{tag}".encode()).hexdigest()


def _parent_hash(left_hash: str, right_hash: str) -> str:
    return hashlib.sha256(f"{left_hash}|{right_hash}".encode()).hexdigest()


def build_improved_mht(tags: Sequence[str]) -> Tuple[Dict[str, Any], str]:
    leaves = [{"h": _leaf_hash(tag), "lN": 1, "p": idx, "tag": tag} for idx, tag in enumerate(tags)]
    if not leaves:
        root = hashlib.sha256(b"empty-tree").hexdigest()
        return {"levels": [[]], "root": root, "tags": []}, root

    levels: List[List[Dict[str, Any]]] = [leaves]
    current = leaves
    parent_position = 0
    while len(current) > 1:
        next_level: List[Dict[str, Any]] = []
        for idx in range(0, len(current), 2):
            left = current[idx]
            right = current[idx + 1] if idx + 1 < len(current) else current[idx]
            node = {
                "h": _parent_hash(left["h"], right["h"]),
                "lN": left["lN"] + right["lN"],
                "p": parent_position,
            }
            next_level.append(node)
            parent_position += 1
        levels.append(next_level)
        current = next_level
    root = current[0]["h"]
    return {"levels": levels, "root": root, "tags": list(tags)}, root


def insert_block_mht(tree: Dict[str, Any], tag: str, index: int | None = None) -> Tuple[Dict[str, Any], str]:
    tags = list(tree.get("tags", []))
    if index is None:
        tags.append(tag)
    else:
        tags.insert(index, tag)
    return build_improved_mht(tags)


def modify_block_mht(tree: Dict[str, Any], index: int, new_tag: str) -> Tuple[Dict[str, Any], str]:
    tags = list(tree.get("tags", []))
    tags[index] = new_tag
    return build_improved_mht(tags)


def delete_block_mht(tree: Dict[str, Any], index: int) -> Tuple[Dict[str, Any], str]:
    tags = list(tree.get("tags", []))
    del tags[index]
    return build_improved_mht(tags)
