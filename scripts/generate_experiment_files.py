from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, List


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "data" / "client_files"
BLOCK_SIZE = 4096
DATASET_VERSION = "dup-mix-paper-real-files-v1"


@dataclass(frozen=True)
class FileSpec:
    name: str
    category: str
    block_count: int
    duplicate_ratio: float
    source: str | None
    shared_ratio: float
    purpose: str


def _block(seed: str, index: int) -> bytes:
    digest = hashlib.sha256(f"{DATASET_VERSION}|{seed}|{index}".encode()).digest()
    out = bytearray()
    counter = 0
    while len(out) < BLOCK_SIZE:
        out.extend(hashlib.sha256(digest + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(out[:BLOCK_SIZE])


def _write_blocks(path: Path, seeds: Iterable[tuple[str, int]]) -> str:
    sha = hashlib.sha256()
    with path.open("wb") as handle:
        for seed, index in seeds:
            block = _block(seed, index)
            handle.write(block)
            sha.update(block)
    return sha.hexdigest()


def _base_specs() -> List[FileSpec]:
    block_counts = [100, 300, 500, 1000, 1200]
    dup_ratios = [0.0, 0.25, 0.5, 0.75, 0.9]
    specs: List[FileSpec] = []
    idx = 1
    for block_count in block_counts:
        for dup_ratio in dup_ratios[:4]:
            specs.append(
                FileSpec(
                    name=f"base_{idx:03d}_b{block_count}_dup{int(dup_ratio * 100):02d}.bin",
                    category="base",
                    block_count=block_count,
                    duplicate_ratio=dup_ratio,
                    source=None,
                    shared_ratio=0.0,
                    purpose="基础文件：覆盖上传、tag/auth 生成、不同块数和文件内部重复率。",
                )
            )
            idx += 1
    return specs


def _file_duplicate_specs(base_specs: List[FileSpec]) -> List[FileSpec]:
    selected = base_specs[::2] + base_specs[1::4][:5]
    return [
        FileSpec(
            name=f"filedup_{idx:03d}_of_{source.name}",
            category="file_duplicate",
            block_count=source.block_count,
            duplicate_ratio=source.duplicate_ratio,
            source=source.name,
            shared_ratio=1.0,
            purpose="文件级去重：内容与 source 完全一致，应命中文件级重复。",
        )
        for idx, source in enumerate(selected, start=1)
    ]


def _block_duplicate_specs(base_specs: List[FileSpec]) -> List[FileSpec]:
    shared_ratios = [0.25, 0.5, 0.75, 0.9, 0.5, 0.75, 0.25]
    specs: List[FileSpec] = []
    for idx in range(35):
        source = base_specs[idx % len(base_specs)]
        shared_ratio = shared_ratios[idx % len(shared_ratios)]
        block_count = source.block_count
        specs.append(
            FileSpec(
                name=(
                    f"blockdup_{idx + 1:03d}_b{block_count}_share"
                    f"{int(shared_ratio * 100):02d}_from_{source.name}"
                ),
                category="block_duplicate",
                block_count=block_count,
                duplicate_ratio=shared_ratio,
                source=source.name,
                shared_ratio=shared_ratio,
                purpose="块级去重：前缀块与 source 共享，剩余块唯一，应命中部分块重复。",
            )
        )
    return specs


def _audit_specs() -> List[FileSpec]:
    plan = [1200] * 8 + [2000] * 8 + [3000] * 4
    return [
        FileSpec(
            name=f"audit_{idx:03d}_b{block_count}_dup75.bin",
            category="audit",
            block_count=block_count,
            duplicate_ratio=0.75,
            source=None,
            shared_ratio=0.0,
            purpose="审计实验：面向 300/460 challenge blocks 的证明生成和验证。",
        )
        for idx, block_count in enumerate(plan, start=1)
    ]


def _update_specs() -> List[FileSpec]:
    plan = [300, 300, 500, 500, 500, 1000, 1000, 1200, 1200, 1200]
    return [
        FileSpec(
            name=f"update_{idx:03d}_b{block_count}_dup50.bin",
            category="update",
            block_count=block_count,
            duplicate_ratio=0.5,
            source=None,
            shared_ratio=0.0,
            purpose="动态更新实验：用于后续插入、修改、删除 HVT 节点。",
        )
        for idx, block_count in enumerate(plan, start=1)
    ]


def build_specs() -> List[FileSpec]:
    base = _base_specs()
    return base + _file_duplicate_specs(base) + _block_duplicate_specs(base) + _audit_specs() + _update_specs()


def _internal_seeds(spec: FileSpec) -> List[tuple[str, int]]:
    unique_count = max(1, int(spec.block_count * (1.0 - spec.duplicate_ratio)))
    seed = spec.name
    return [(seed, idx % unique_count) for idx in range(spec.block_count)]


def _block_duplicate_seeds(spec: FileSpec) -> List[tuple[str, int]]:
    if not spec.source:
        raise ValueError(f"{spec.name} missing source")
    shared_count = int(spec.block_count * spec.shared_ratio)
    seeds: List[tuple[str, int]] = []
    for idx in range(spec.block_count):
        if idx < shared_count:
            seeds.append((spec.source, idx))
        else:
            seeds.append((spec.name, idx - shared_count))
    return seeds


def generate_dataset(output_dir: Path, overwrite: bool) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    specs = build_specs()
    manifest_files = []
    generated = 0
    skipped = 0

    for spec in specs:
        target = output_dir / spec.name
        if target.exists() and not overwrite:
            skipped += 1
        elif spec.category == "file_duplicate":
            if not spec.source:
                raise ValueError(f"{spec.name} missing source")
            source = output_dir / spec.source
            if not source.exists():
                raise FileNotFoundError(f"{spec.name} needs source {source}")
            shutil.copyfile(source, target)
            generated += 1
        else:
            seeds = _block_duplicate_seeds(spec) if spec.category == "block_duplicate" else _internal_seeds(spec)
            _write_blocks(target, seeds)
            generated += 1

        sha = hashlib.sha256(target.read_bytes()).hexdigest()
        row = asdict(spec)
        row.update(
            {
                "path": str(target.relative_to(PROJECT_ROOT)),
                "size_bytes": target.stat().st_size,
                "sha256": sha,
                "block_size": BLOCK_SIZE,
            }
        )
        manifest_files.append(row)

    summary = {
        "dataset_version": DATASET_VERSION,
        "block_size": BLOCK_SIZE,
        "file_count": len(manifest_files),
        "generated": generated,
        "skipped_existing": skipped,
        "total_size_bytes": sum(item["size_bytes"] for item in manifest_files),
        "categories": {
            category: sum(1 for item in manifest_files if item["category"] == category)
            for category in sorted({item["category"] for item in manifest_files})
        },
        "files": manifest_files,
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate paper-style real files for Dup_Mix uploads.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--overwrite", action="store_true", help="Overwrite generated files if they already exist.")
    args = parser.parse_args()

    summary = generate_dataset(args.output_dir, args.overwrite)
    print(f"[dataset] output_dir={args.output_dir}")
    print(f"[dataset] file_count={summary['file_count']}")
    print(f"[dataset] generated={summary['generated']} skipped_existing={summary['skipped_existing']}")
    print(f"[dataset] total_size_bytes={summary['total_size_bytes']}")
    print(f"[dataset] categories={summary['categories']}")
    print(f"[dataset] manifest={args.output_dir / 'manifest.json'}")


if __name__ == "__main__":
    main()
