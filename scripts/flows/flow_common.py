from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.chain import connect_chain, deploy_contract
from src.crypto import CryptoEngine, setup
from src.models import CSPState, UserState
from src.protocol import upload_and_dedup_protocol
from src.utils import compressed_public_key_from_private, load_environment


OWNER_ADDRESS = "0x24291Ea0B8aB706e1a576beBC869A2b63072f265"
OWNER_PRIVATE_KEY = "0x308539265331010d37c2e16d3b27fcc6a71dff6ffcb26175d4fc2af0e7b36dd8"
BUYER_ADDRESS = "0x2ad9a1698a5309dB005cea681150362Ab99Dc1B3"
BUYER_PRIVATE_KEY = "0x19d737f6b2ac3b146ff985de0dded5b5d11b694f26bb0dd92b0f75c88ad04897"
CSP_ADDRESS = "0x7021Fb52487AC1c1733cC47A846dB474B25D01Ab"
CSP_PRIVATE_KEY = "0x61cabe658a8c206a440bfb65641c9a8a76fcd3915c9e9064fc4763b9e2c4ea83"


@dataclass
class FlowRuntime:
    engine: CryptoEngine
    chain: Any
    csp: CSPState
    owner: UserState
    buyer: UserState


def build_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--real-chain", action="store_true", help="Use Ganache/web3 instead of the in-memory chain.")
    parser.add_argument("--sectors-per-block", type=int, default=128)
    parser.add_argument("--public-blocks", default="0", help="Comma-separated public block indices.")
    return parser


def parse_public_blocks(raw: str) -> list[int]:
    return [int(item.strip()) for item in raw.split(",") if item.strip()]


def build_user(address: str, private_key: str, uid: str) -> UserState:
    return UserState(
        address=address,
        private_key=private_key,
        uid=uid,
        public_key=compressed_public_key_from_private(private_key),
    )


def build_runtime(sectors_per_block: int, real_chain: bool) -> FlowRuntime:
    load_environment()
    params = setup(sectors_per_block=sectors_per_block, s=b"flow-demo-secret")
    engine = CryptoEngine(params)
    chain = deploy_contract(
        connect_chain(chain_id=1337, force_mock=not real_chain, require_real=real_chain),
        str(ROOT / "contracts" / "AuditSystem.sol"),
    )
    csp = CSPState(address=CSP_ADDRESS, private_key=CSP_PRIVATE_KEY, storage_capacity=10**9)
    owner = build_user(OWNER_ADDRESS, OWNER_PRIVATE_KEY, "flow-owner")
    buyer = build_user(BUYER_ADDRESS, BUYER_PRIVATE_KEY, "flow-buyer")
    return FlowRuntime(engine=engine, chain=chain, csp=csp, owner=owner, buyer=buyer)


def sample_file_bytes() -> bytes:
    public_part = (b"public-data-block|" * 260)[:4096]
    private_part = (b"private-data-block|" * 260)[:4096]
    return public_part + private_part


def prepare_uploaded_file(rt: FlowRuntime, public_blocks: list[int]) -> tuple[bytes, dict[str, Any]]:
    file_bytes = sample_file_bytes()
    upload = upload_and_dedup_protocol(
        rt.owner,
        file_bytes,
        rt.csp,
        rt.chain,
        rt.engine,
        public_block_indices=public_blocks,
    )
    return file_bytes, upload


def printable(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(k): printable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [printable(v) for v in value]
    if isinstance(value, set):
        return sorted(printable(v) for v in value)
    return value


def print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(printable(payload), indent=2, sort_keys=True))
