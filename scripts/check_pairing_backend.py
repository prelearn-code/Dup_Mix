from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.crypto import setup


def main() -> None:
    params = setup(sectors_per_block=8, s=b"backend-check")
    print(f"pairing_backend={params.pairing_backend}")
    print(f"use_pbc={params.use_pbc}")
    print(f"pairing_strict={params.pairing_strict}")
    print(f"note={params.implementation_note}")


if __name__ == "__main__":
    main()
