from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class GlobalParams:
    block_size: int
    sectors_per_block: int
    duplication_ratio: float
    average_runs: int
    chain_id: int
    s_param: bytes
    group_order: int
    generator: int
    r_values: List[int]
    use_pbc: bool = False
    pairing_backend: str = "fallback"
    pairing_strict: bool = False
    implementation_note: str = "Fallback pairing surrogate over secp256k1 scalar field."


@dataclass
class UserState:
    address: str
    private_key: str
    uid: str
    public_key: str
    mu: int = 0
    UID: bytes = b""
    W: bytes = b""
    local_files: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class FileState:
    file_id: str
    owner_address: str
    file_size: int
    file_hash: str
    t: str
    block_ids: List[str]
    block_tags: List[str]
    public_blocks: Set[int] = field(default_factory=set)
    is_deduplicated: bool = False
    mht_root: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CSPState:
    address: str
    private_key: str
    storage_capacity: int
    used_capacity: int = 0
    files: Dict[str, FileState] = field(default_factory=dict)
    blocks: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    file_index: Dict[str, str] = field(default_factory=dict)
    block_index: Dict[str, str] = field(default_factory=dict)
    authenticators: Dict[str, Dict[str, int]] = field(default_factory=dict)
    key_ciphers: Dict[str, Dict[str, bytes]] = field(default_factory=dict)
    ownership: Dict[str, str] = field(default_factory=dict)
    audit_history: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ChainState:
    backend: str
    chain_id: int
    contract_address: str = ""
    current_block: int = 0
    web3_provider: Any = None
    contract: Any = None
    contract_abi: Optional[List[Dict[str, Any]]] = None
    balances: Dict[str, int] = field(default_factory=dict)
    uploads: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    challenges: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    proof_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    transfers: Dict[str, Dict[str, Any]] = field(default_factory=dict)
