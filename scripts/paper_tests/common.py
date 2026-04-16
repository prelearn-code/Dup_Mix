from __future__ import annotations

import csv
import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = PROJECT_ROOT / "results" / "paper_tests"


def ensure_results_dir() -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    return RESULTS_DIR


def now_ms() -> float:
    return time.perf_counter() * 1000.0


def avg_ms(samples: Sequence[float]) -> float:
    return sum(samples) / max(1, len(samples))


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    # Some benchmarks output mixed row shapes (for example, upload vs audit fields).
    # Build a stable superset header and fill missing keys with empty strings.
    fieldnames: List[str] = []
    seen = set()
    for row in rows:
        for key in row.keys():
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def sizeof_int(value: int) -> int:
    if value == 0:
        return 1
    return (value.bit_length() + 7) // 8


def sizeof_value(value: Any) -> int:
    if isinstance(value, bytes):
        return len(value)
    if isinstance(value, str):
        return len(value.encode())
    if isinstance(value, bool):
        return 1
    if isinstance(value, int):
        return sizeof_int(value)
    if isinstance(value, dict):
        return sum(sizeof_value(k) + sizeof_value(v) for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return sum(sizeof_value(item) for item in value)
    return len(str(value).encode())


def flatten(blocks: Iterable[bytes]) -> bytes:
    return b"".join(blocks)
