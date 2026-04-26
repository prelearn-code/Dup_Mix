from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

import yaml
from dotenv import load_dotenv


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("DupMixSystem")


class Timer:
    def __enter__(self) -> "Timer":
        self.start = time.perf_counter()
        return self

    def __exit__(self, *args: object) -> None:
        self.end = time.perf_counter()
        self.interval = self.end - self.start


class ConfigLoader:
    def __init__(self, config_path: str = "config.yaml", env_path: str = ".env") -> None:
        self.config_path = Path(config_path)
        self.env_path = Path(env_path)
        self.config: Dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if self.env_path.exists():
            load_dotenv(self.env_path)
        if self.config_path.exists():
            self.config = yaml.safe_load(self.config_path.read_text()) or {}

    def get(self, key: str, default: Any = None) -> Any:
        return os.getenv(key, self.config.get(key, default))


def load_environment(env_path: str = ".env") -> None:
    env_file = Path(env_path)
    if env_file.exists():
        load_dotenv(env_file)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ensure_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode()
    if isinstance(value, int):
        return int_to_bytes(value)
    raise TypeError(f"Unsupported byte conversion for {type(value)!r}")


def int_to_bytes(value: int, length: int | None = None) -> bytes:
    if value == 0 and not length:
        return b"\x00"
    if length is None:
        length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")


def serialize_bytes_list(items: Sequence[bytes]) -> bytes:
    return json.dumps([item.hex() for item in items]).encode()


def deserialize_bytes_list(data: bytes) -> List[bytes]:
    return [bytes.fromhex(item) for item in json.loads(data.decode())]


def serialize_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True).encode()


def chunk_bytes(data: bytes, size: int) -> List[bytes]:
    return [data[i : i + size] for i in range(0, len(data), size)]


def pad_last_block(block: bytes, block_size: int) -> bytes:
    if len(block) == block_size:
        return block
    return block + (b"\x00" * (block_size - len(block)))

# 按照4kb/128个扇区划分文件数据，最后一个块不足4kb时补零
def split_file_into_blocks_and_sectors(
    file_path: str | None = None,
    block_size: int = 4096,
    sectors_per_block: int = 128,
    data: bytes | None = None,
) -> List[List[bytes]]:
    if data is None:
        if file_path is None:
            raise ValueError("Either file_path or data must be provided.")
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File {file_path} does not exist.")
        data = path.read_bytes()

    sector_size = block_size // sectors_per_block
    blocks: List[List[bytes]] = []
    for offset in range(0, len(data), block_size):
        block = pad_last_block(data[offset : offset + block_size], block_size)
        blocks.append(chunk_bytes(block, sector_size))
    if not blocks:
        blocks.append(chunk_bytes(b"\x00" * block_size, sector_size))
    return blocks

# 为了配对运算中对块数据的哈希计算，扇区内数据需要先合并成一个连续的字节串
def flatten_block(block: Sequence[bytes]) -> bytes:
    return b"".join(block)

# 为了配对运算中对块数据的哈希计算，扇区内数据需要先合并成一个连续的字节串
def flatten_blocks(blocks: Iterable[Sequence[bytes]]) -> bytes:
    return b"".join(flatten_block(block) for block in blocks)

# 为了配对运算中对块数据的哈希计算，扇区内数据需要先合并成一个连续的字节串
def compressed_public_key_from_private(private_key_hex: str) -> str:
    from coincurve import PrivateKey

    normalized = private_key_hex[2:] if private_key_hex.startswith("0x") else private_key_hex
    return PrivateKey(bytes.fromhex(normalized)).public_key.format(compressed=True).hex()
