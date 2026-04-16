from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.paper_tests.benchmarks import bench_f_communication, save_result


def main() -> None:
    parser = argparse.ArgumentParser(description="Metric F: communication benchmark")
    parser.add_argument("--blocks", default="1000,3000,5000", help="Comma-separated block counts")
    parser.add_argument("--challenge-blocks", default="300,460", help="Comma-separated challenge counts")
    parser.add_argument("--dup-ratio", type=float, default=0.75)
    parser.add_argument("--private-ratio", type=float, default=0.5)
    args = parser.parse_args()

    block_counts = [int(x.strip()) for x in args.blocks.split(",") if x.strip()]
    challenge_counts = [int(x.strip()) for x in args.challenge_blocks.split(",") if x.strip()]
    result = bench_f_communication(block_counts, challenge_counts, args.dup_ratio, args.private_ratio)
    paths = save_result(result)
    print(f"[F] done. csv={paths['csv']} json={paths['json']}", flush=True)


if __name__ == "__main__":
    main()
