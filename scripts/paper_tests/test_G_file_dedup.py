from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.paper_tests.benchmarks import bench_g_file_dedup, save_result


def main() -> None:
    parser = argparse.ArgumentParser(description="Metric G: file-level dedup benchmark")
    parser.add_argument("--file-blocks", type=int, default=2000)
    parser.add_argument("--private-ratio", type=float, default=0.5)
    parser.add_argument("--challenge-blocks", type=int, default=460)
    parser.add_argument("--dup-ratio", type=float, default=0.75)
    args = parser.parse_args()

    result = bench_g_file_dedup(args.file_blocks, args.private_ratio, args.challenge_blocks, args.dup_ratio)
    paths = save_result(result)
    print(f"[G] done. csv={paths['csv']} json={paths['json']}", flush=True)


if __name__ == "__main__":
    main()
