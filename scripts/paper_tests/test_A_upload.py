from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.paper_tests.benchmarks import bench_a_upload, save_result


def main() -> None:
    parser = argparse.ArgumentParser(description="Metric A: upload/tag/auth benchmark")
    parser.add_argument("--blocks", default="100,300,500", help="Comma-separated block counts")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--dup-ratio", type=float, default=0.75)
    parser.add_argument("--private-ratio", type=float, default=0.5)
    args = parser.parse_args()

    block_counts = [int(x.strip()) for x in args.blocks.split(",") if x.strip()]
    result = bench_a_upload(block_counts, args.repeats, args.dup_ratio, args.private_ratio)
    paths = save_result(result)
    print(f"[A] done. csv={paths['csv']} json={paths['json']}", flush=True)


if __name__ == "__main__":
    main()
