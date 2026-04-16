from __future__ import annotations

from typing import List, Sequence

from .models import CSPState, FileState


def file_level_dedup_check(csp_state: CSPState, t_hex: str) -> bool:
    return t_hex in csp_state.file_index


def block_level_dedup_check(csp_state: CSPState, tags: Sequence[str]) -> List[int]:
    return [index for index, tag in enumerate(tags) if tag not in csp_state.block_index]


def store_upload_metadata(csp_state: CSPState, file_state: FileState) -> None:
    csp_state.files[file_state.file_id] = file_state
    csp_state.file_index[file_state.t] = file_state.file_id
    csp_state.ownership[file_state.file_id] = file_state.owner_address


def store_authenticator(csp_state: CSPState, block_id: str, sigma: int, y_value: int, y_group: int) -> None:
    csp_state.authenticators[block_id] = {"sigma": sigma, "y": y_value, "Y": y_group}


def store_key_cipher(csp_state: CSPState, block_id: str, owner_address: str, key_cipher: bytes) -> None:
    csp_state.key_ciphers.setdefault(block_id, {})[owner_address] = key_cipher


def update_ownership_record(csp_state: CSPState, file_id: str, new_owner: str) -> None:
    csp_state.ownership[file_id] = new_owner
    csp_state.files[file_id].owner_address = new_owner
