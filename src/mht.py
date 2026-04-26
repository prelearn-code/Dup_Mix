from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Sequence, Tuple


def _leaf_hash(tag: str) -> str:
    # In the paper's improved MHT, a leaf hash is the block tag itself: h_i=tg_i.
    return tag


def _parent_hash(left_hash: str, right_hash: str) -> str:
    return hashlib.sha256(f"{left_hash}|{right_hash}".encode()).hexdigest()


def _leaf_node(tag: str, position: int) -> Dict[str, Any]:
    return {"h": _leaf_hash(tag), "lN": 1, "p": position, "tag": tag}


def _parent_node(left: Dict[str, Any], right: Dict[str, Any], position: int) -> Dict[str, Any]:
    return {
        "h": _parent_hash(left["h"], right["h"]),
        "lN": left["lN"] + right["lN"],
        "p": position,
        "left": left,
        "right": right,
    }


def _refresh_node(node: Dict[str, Any]) -> Dict[str, Any]:
    if "tag" in node:
        node["h"] = _leaf_hash(node["tag"])
        node["lN"] = 1
        return node
    node["left"] = _refresh_node(node["left"])
    node["right"] = _refresh_node(node["right"])
    node["h"] = _parent_hash(node["left"]["h"], node["right"]["h"])
    node["lN"] = node["left"]["lN"] + node["right"]["lN"]
    return node


def _collect_levels(root: Dict[str, Any]) -> List[List[Dict[str, Any]]]:
    by_depth: Dict[int, List[Dict[str, Any]]] = {}

    def walk(node: Dict[str, Any], depth: int) -> None:
        by_depth.setdefault(depth, []).append(node)
        if "tag" not in node:
            walk(node["left"], depth + 1)
            walk(node["right"], depth + 1)

    walk(root, 0)
    return [by_depth[depth] for depth in sorted(by_depth.keys(), reverse=True)]


def _finalize_tree(root: Dict[str, Any], tags: Sequence[str]) -> Tuple[Dict[str, Any], str]:
    root["p"] = 0
    root = _refresh_node(root)
    tree = {"levels": _collect_levels(root), "root": root["h"], "tags": list(tags), "node": root}
    return tree, root["h"]


def _build_from_tags(tags: Sequence[str]) -> Dict[str, Any]:
    current = [_leaf_node(tag, idx + 1) for idx, tag in enumerate(tags)]
    while len(current) > 1:
        next_level: List[Dict[str, Any]] = []
        for idx in range(0, len(current), 2):
            if idx + 1 >= len(current):
                next_level.append(current[idx])
                continue
            next_level.append(_parent_node(current[idx], current[idx + 1], (idx // 2) + 1))
        current = next_level
    current[0]["p"] = 0
    return current[0]


def _leaf_count(node: Dict[str, Any]) -> int:
    return int(node["lN"])

# 动态修改 MHT：根据索引定位到对应叶子节点，替换标签并重算路径上的哈希值，返回更新后的树结构
def _modify_at(node: Dict[str, Any], index: int, new_tag: str) -> Dict[str, Any]:
    if "tag" in node:
        if index != 0:
            raise IndexError("MHT modify index out of range")
        node["tag"] = new_tag
        return _refresh_node(node)
    left_count = _leaf_count(node["left"])
    if index < left_count:
        node["left"] = _modify_at(node["left"], index, new_tag)
    else:
        node["right"] = _modify_at(node["right"], index - left_count, new_tag)
    return _refresh_node(node)

# 插入新标签：在指定位置插入新叶子节点，并局部更新受影响路径的哈希值，返回新的树结构
def _insert_at(node: Dict[str, Any], index: int, new_leaf: Dict[str, Any]) -> Dict[str, Any]:
    if "tag" in node:
        if index == 0:
            return _parent_node(new_leaf, node, node["p"])
        if index == 1:
            return _parent_node(node, new_leaf, node["p"])
        raise IndexError("MHT insert index out of range")
    left_count = _leaf_count(node["left"])
    if index <= left_count:
        node["left"] = _insert_at(node["left"], index, new_leaf)
    else:
        node["right"] = _insert_at(node["right"], index - left_count, new_leaf)
    return _refresh_node(node)

# 删除标签：删除指定位置的叶子节点后提升剩余 sibling，并重算路径上的哈希值，返回更新后的树结构或 None（当树变空时）
def _delete_at(node: Dict[str, Any], index: int) -> Dict[str, Any] | None:
    if "tag" in node:
        if index != 0:
            raise IndexError("MHT delete index out of range")
        return None
    left_count = _leaf_count(node["left"])
    if index < left_count:
        node["left"] = _delete_at(node["left"], index)
        if node["left"] is None:
            return node["right"]
    else:
        node["right"] = _delete_at(node["right"], index - left_count)
        if node["right"] is None:
            return node["left"]
    return _refresh_node(node)


# 建立改进的 MHT 结构，包含每个节点的哈希值、子树大小、位置索引和原始标签信息，方便后续动态操作和验证
def build_improved_mht(tags: Sequence[str]) -> Tuple[Dict[str, Any], str]:
    if not tags:
        root = hashlib.sha256(b"empty-tree").hexdigest()
        return {"levels": [[]], "root": root, "tags": []}, root
    return _finalize_tree(_build_from_tags(tags), tags)


# 插入块级标签：在指定位置插入新标签，并局部更新受影响路径，返回新的树结构和根哈希
def insert_block_mht(tree: Dict[str, Any], tag: str, index: int | None = None) -> Tuple[Dict[str, Any], str]:
    tags = list(tree.get("tags", []))
    insert_at = len(tags) if index is None else index
    if insert_at < 0 or insert_at > len(tags):
        raise IndexError("MHT insert index out of range")
    tags.insert(insert_at, tag)
    if len(tags) == 1:
        return build_improved_mht(tags)
    root = tree.get("node") or _build_from_tags(tree.get("tags", []))
    updated = _insert_at(root, insert_at, _leaf_node(tag, insert_at + 1))
    return _finalize_tree(updated, tags)


# 修改块级标签：在指定位置替换旧标签为新标签，并重算从叶子到根的路径
def modify_block_mht(tree: Dict[str, Any], index: int, new_tag: str) -> Tuple[Dict[str, Any], str]:
    tags = list(tree.get("tags", []))
    if index < 0 or index >= len(tags):
        raise IndexError("MHT modify index out of range")
    tags[index] = new_tag
    root = tree.get("node") or _build_from_tags(tree.get("tags", []))
    return _finalize_tree(_modify_at(root, index, new_tag), tags)


# 删除块级标签：删除叶子后提升剩余 sibling，并重算到根的路径
def delete_block_mht(tree: Dict[str, Any], index: int) -> Tuple[Dict[str, Any], str]:
    tags = list(tree.get("tags", []))
    if index < 0 or index >= len(tags):
        raise IndexError("MHT delete index out of range")
    del tags[index]
    if not tags:
        return build_improved_mht(tags)
    root = tree.get("node") or _build_from_tags(tree.get("tags", []))
    updated = _delete_at(root, index)
    if updated is None:
        return build_improved_mht(tags)
    return _finalize_tree(updated, tags)
