from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.paper_tests.common import ensure_results_dir, write_csv, write_json


def _read_csv_rows(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _to_float(value: Any) -> Optional[float]:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except Exception:
        return None


def _pick_row(rows: List[Dict[str, str]], **conds: Any) -> Optional[Dict[str, str]]:
    for row in rows:
        ok = True
        for key, expected in conds.items():
            if str(row.get(key, "")).strip() != str(expected):
                ok = False
                break
        if ok:
            return row
    return None


def _status(delta_pct: Optional[float], comparable: bool) -> str:
    if not comparable or delta_pct is None:
        return "not-comparable"
    d = abs(delta_pct)
    if d <= 10:
        return "match"
    if d <= 30:
        return "close"
    return "mismatch"


def _delta_pct(paper: Optional[float], measured: Optional[float]) -> Optional[float]:
    if paper is None or measured is None or paper == 0:
        return None
    return (measured - paper) / paper * 100.0


def _load_run_meta(results_dir: Path) -> Dict[str, Any]:
    for name in ("run_meta_full.json", "run_meta_smoke.json"):
        path = results_dir / name
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return {}
    return {}


def _build_rows(results_dir: Path) -> List[Dict[str, Any]]:
    run_meta = _load_run_meta(results_dir)
    comparable_flag = bool(run_meta.get("comparable", False))

    b_rows = _read_csv_rows(results_dir / "B_prove.csv")
    c_rows = _read_csv_rows(results_dir / "C_verify.csv")
    e_rows = _read_csv_rows(results_dir / "E_update.csv")
    g_rows = _read_csv_rows(results_dir / "G_file_level_dedup.csv")
    h_rows = _read_csv_rows(results_dir / "H_audit_gas.csv")
    i_rows = _read_csv_rows(results_dir / "I_transfer_gas.csv")

    specs = [
        # B
        {"id": "B_z300_prove_ms", "paper": 7.05, "unit": "ms", "file": "B_prove.csv", "key": "avg_prove_ms", "row": _pick_row(b_rows, challenge_blocks=300)},
        {"id": "B_z460_prove_ms", "paper": 10.82, "unit": "ms", "file": "B_prove.csv", "key": "avg_prove_ms", "row": _pick_row(b_rows, challenge_blocks=460)},
        # C
        {"id": "C_z300_verify_ms", "paper": 613.92, "unit": "ms", "file": "C_verify.csv", "key": "avg_verify_ms", "row": _pick_row(c_rows, challenge_blocks=300)},
        {"id": "C_z460_verify_ms", "paper": 883.36, "unit": "ms", "file": "C_verify.csv", "key": "avg_verify_ms", "row": _pick_row(c_rows, challenge_blocks=460)},
        # E
        {"id": "E_update_1000_total_s", "paper": 2.78, "unit": "s", "file": "E_update.csv", "key": "total_update_ms", "row": _pick_row(e_rows, num_updates=1000), "convert_ms_to_s": True},
        # G
        {"id": "G_file_tag_s", "paper": 0.0008, "unit": "s", "file": "G_file_level_dedup.csv", "key": "file_tag_ms", "row": _pick_row(g_rows, file_blocks=2000, private_ratio=0.5, challenge_blocks=460), "convert_ms_to_s": True},
        # H gas
        {"id": "H_challenge_gas", "paper": 3.90e5, "unit": "gas", "file": "H_audit_gas.csv", "key": "challenge_gas", "row": h_rows[0] if h_rows else None},
        {"id": "H_prove_gas", "paper": 1.83e5, "unit": "gas", "file": "H_audit_gas.csv", "key": "prove_gas", "row": h_rows[0] if h_rows else None},
        {"id": "H_verify_gas", "paper": 2.35e6, "unit": "gas", "file": "H_audit_gas.csv", "key": "verify_gas", "row": h_rows[0] if h_rows else None},
        # I gas
        {"id": "I_request_gas", "paper": 1.48e5, "unit": "gas", "file": "I_transfer_gas.csv", "key": "request_gas", "row": i_rows[0] if i_rows else None},
        {"id": "I_owner_verify_gas", "paper": 1.43e5, "unit": "gas", "file": "I_transfer_gas.csv", "key": "owner_verify_gas", "row": i_rows[0] if i_rows else None},
        {"id": "I_csp_update_gas", "paper": 1.37e5, "unit": "gas", "file": "I_transfer_gas.csv", "key": "csp_update_gas", "row": i_rows[0] if i_rows else None},
        {"id": "I_finalize_gas", "paper": 0.48e5, "unit": "gas", "file": "I_transfer_gas.csv", "key": "finalize_gas", "row": i_rows[0] if i_rows else None},
    ]

    rows: List[Dict[str, Any]] = []
    for spec in specs:
        measured: Optional[float] = None
        if spec["row"] is not None:
            measured = _to_float(spec["row"].get(spec["key"]))
            if measured is not None and spec.get("convert_ms_to_s"):
                measured = measured / 1000.0
        delta = _delta_pct(spec["paper"], measured)
        comparable = comparable_flag and measured is not None
        rows.append(
            {
                "metric_id": spec["id"],
                "paper_value": spec["paper"],
                "measured_value": "" if measured is None else round(measured, 6),
                "unit": spec["unit"],
                "delta_pct": "" if delta is None else round(delta, 2),
                "status": _status(delta, comparable),
                "source_file": spec["file"],
                "note": "missing measured data" if measured is None else "",
            }
        )
    return rows


def _build_markdown(rows: List[Dict[str, Any]], run_meta: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# Paper vs Measured Report")
    lines.append("")
    lines.append("## Run Context")
    lines.append("")
    lines.append(f"- comparable: `{run_meta.get('comparable', False)}`")
    mode_meta = run_meta.get("mode_meta", {})
    if mode_meta:
        lines.append(f"- mode: `{mode_meta.get('name', 'unknown')}`")
        lines.append(f"- chain_mode: `{mode_meta.get('chain_mode', 'unknown')}`")
        lines.append(f"- paper_scale: `{mode_meta.get('paper_scale', False)}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| metric_id | paper | measured | unit | delta_pct | status | source |")
    lines.append("| --- | ---: | ---: | --- | ---: | --- | --- |")
    for r in rows:
        lines.append(
            f"| {r['metric_id']} | {r['paper_value']} | {r['measured_value']} | "
            f"{r['unit']} | {r['delta_pct']} | {r['status']} | {r['source_file']} |"
        )
    lines.append("")
    lines.append("status rule: `|delta|<=10% => match`, `<=30% => close`, else `mismatch`.")
    lines.append("When run metadata is not comparable, status is `not-comparable`.")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Build paper-vs-measured comparison report.")
    parser.add_argument("--results-dir", default=str(ensure_results_dir()))
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    rows = _build_rows(results_dir)
    run_meta = _load_run_meta(results_dir)
    payload = {"name": "paper_vs_measured_report", "rows": rows, "run_meta": run_meta}

    summary_csv = results_dir / "paper_vs_measured_summary.csv"
    summary_json = results_dir / "paper_vs_measured_summary.json"
    summary_md = results_dir / "paper_vs_measured_report.md"

    write_csv(summary_csv, rows)
    write_json(summary_json, payload)
    summary_md.write_text(_build_markdown(rows, run_meta), encoding="utf-8")

    print(f"[report] csv={summary_csv}")
    print(f"[report] json={summary_json}")
    print(f"[report] md={summary_md}")


if __name__ == "__main__":
    main()
