from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.paper_tests.benchmarks import bench_e_update, save_result


def main() -> None:
    parser = argparse.ArgumentParser(description="Metric E: dynamic update benchmark")
    parser.add_argument("--updates", type=int, default=1000)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--n-blocks", type=int, default=1200)
    parser.add_argument("--dup-ratio", type=float, default=0.75)
    parser.add_argument("--private-ratio", type=float, default=0.5)
    args = parser.parse_args()

    result = bench_e_update(args.updates, args.repeats, args.n_blocks, args.dup_ratio, args.private_ratio)
    paths = save_result(result)
    print(f"[E] done. csv={paths['csv']} json={paths['json']}", flush=True)


if __name__ == "__main__":
    main()
