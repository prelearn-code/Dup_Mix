from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.paper_tests.benchmarks import (
    bench_a_upload,
    bench_b_prove,
    bench_c_verify,
    bench_d_encrypt_decrypt,
    bench_e_update,
    bench_f_communication,
    bench_g_file_dedup,
    save_result,
)
from scripts.paper_tests.common import ensure_results_dir


def _load_config(path: Path) -> Dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _run_one(mode_cfg: Dict[str, Any], selected_metrics: List[str]) -> None:
    chain_mode = str(mode_cfg.get("_meta", {}).get("chain_mode", "mock")).lower()
    os.environ["DUPMIX_CHAIN_MODE"] = chain_mode
    metric_set = {m.lower() for m in selected_metrics}
    run_all = "all" in metric_set
    results = []
    if run_all or "a" in metric_set:
        a = mode_cfg["a"]
        results.append(bench_a_upload(a["blocks"], a["repeats"], a["dup_ratio"], a["private_ratio"]))
    if run_all or "b" in metric_set:
        b = mode_cfg["b"]
        results.append(bench_b_prove(b["challenge_blocks"], b["repeats"], b["n_blocks"], b["dup_ratio"], b["private_ratio"]))
    if run_all or "c" in metric_set:
        c = mode_cfg["c"]
        results.append(bench_c_verify(c["challenge_blocks"], c["repeats"], c["n_blocks"], c["dup_ratio"], c["private_ratio"]))
    if run_all or "d" in metric_set:
        d = mode_cfg["d"]
        results.append(bench_d_encrypt_decrypt(d["private_ratios"], d["repeats"], d["n_blocks"], d["dup_ratio"]))
    if run_all or "e" in metric_set:
        e = mode_cfg["e"]
        results.append(bench_e_update(e["updates"], e["repeats"], e["n_blocks"], e["dup_ratio"], e["private_ratio"]))
    if run_all or "f" in metric_set:
        f = mode_cfg["f"]
        results.append(bench_f_communication(f["blocks"], f["challenge_blocks"], f["dup_ratio"], f["private_ratio"]))
    if run_all or "g" in metric_set:
        g = mode_cfg["g"]
        results.append(bench_g_file_dedup(g["file_blocks"], g["private_ratio"], g["challenge_blocks"], g["dup_ratio"]))

    metas: List[Dict[str, Any]] = []
    for result in results:
        paths = save_result(result)
        if result.get("meta"):
            metas.append(result["meta"])
        print(f"[paper_repro] {result['name']} -> csv={paths['csv']}", flush=True)
    run_meta = {
        "mode_meta": mode_cfg.get("_meta", {}),
        "bench_runtime_meta": metas,
        "comparable": bool(mode_cfg.get("_meta", {}).get("paper_scale")) and any(m.get("comparable", False) for m in metas),
    }
    out_dir = ensure_results_dir()
    meta_path = out_dir / f"run_meta_{mode_cfg.get('_meta', {}).get('name', 'unknown')}.json"
    meta_path.write_text(json.dumps(run_meta, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[paper_repro] run_meta -> {meta_path}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run paper-style A-G reproduction with config-driven parameters.")
    parser.add_argument("--mode", choices=["smoke", "full"], default="smoke")
    parser.add_argument("--metrics", default="all", help="Comma-separated list from: a,b,c,d,e,f,g,all")
    parser.add_argument("--config", default=str(ROOT / "configs" / "paper_repro.yaml"))
    args = parser.parse_args()

    cfg = _load_config(Path(args.config))
    if args.mode not in cfg:
        raise ValueError(f"Mode {args.mode!r} not found in config {args.config}")
    selected_metrics = [m.strip().lower() for m in args.metrics.split(",") if m.strip()]
    if not selected_metrics:
        selected_metrics = ["all"]

    print(f"[paper_repro] mode={args.mode} metrics={','.join(selected_metrics)}", flush=True)
    mode_cfg = dict(cfg[args.mode])
    mode_cfg.setdefault("_meta", {})
    mode_cfg["_meta"]["name"] = args.mode
    _run_one(mode_cfg, selected_metrics)
    print("[paper_repro] finished", flush=True)


if __name__ == "__main__":
    main()
