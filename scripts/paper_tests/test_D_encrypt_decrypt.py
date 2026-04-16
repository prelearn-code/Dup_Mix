from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.paper_tests.benchmarks import bench_d_encrypt_decrypt, save_result


def main() -> None:
    parser = argparse.ArgumentParser(description="Metric D: encrypt/decrypt benchmark")
    parser.add_argument("--private-ratios", default="0.2,0.5,0.8,1.0", help="Comma-separated private ratios")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--n-blocks", type=int, default=300)
    parser.add_argument("--dup-ratio", type=float, default=0.75)
    args = parser.parse_args()

    ratios = [float(x.strip()) for x in args.private_ratios.split(",") if x.strip()]
    result = bench_d_encrypt_decrypt(ratios, args.repeats, args.n_blocks, args.dup_ratio)
    paths = save_result(result)
    print(f"[D] done. csv={paths['csv']} json={paths['json']}", flush=True)


if __name__ == "__main__":
    main()
