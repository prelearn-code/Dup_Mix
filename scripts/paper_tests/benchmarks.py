from __future__ import annotations

import random
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Sequence

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.chain import connect_chain, create_audit_request, deploy_contract
from src.crypto import CryptoEngine, setup
from src.models import CSPState, UserState
from src.protocol import (
    insert_protocol,
    proof_gen,
    upload_and_dedup_protocol,
    verify_proof_protocol,
)
from src.utils import compressed_public_key_from_private, split_file_into_blocks_and_sectors

from .common import avg_ms, ensure_results_dir, flatten, now_ms, write_csv, write_json


@dataclass
class Runtime:
    engine: CryptoEngine
    chain: Any
    csp: CSPState
    user1: UserState
    user2: UserState
    chain_mode: str


def build_user(address: str, private_key: str, uid: str) -> UserState:
    return UserState(
        address=address,
        private_key=private_key,
        uid=uid,
        public_key=compressed_public_key_from_private(private_key),
    )


def build_runtime(sectors_per_block: int = 128, chain_mode: str | None = None) -> Runtime:
    chain_mode_value = (chain_mode or os.getenv("DUPMIX_CHAIN_MODE", "mock")).strip().lower()
    if chain_mode_value not in {"mock", "real"}:
        chain_mode_value = "mock"
    params = setup(sectors_per_block=sectors_per_block, s=b"paper-benchmark")
    engine = CryptoEngine(params)
    print(
        f"[runtime] pairing_backend={params.pairing_backend} use_pbc={params.use_pbc} "
        f"pairing_strict={params.pairing_strict} chain_mode={chain_mode_value}",
        flush=True,
    )
    chain = deploy_contract(
        connect_chain(
            chain_id=1337,
            force_mock=(chain_mode_value == "mock"),
            require_real=(chain_mode_value == "real"),
        ),
        str(ROOT / "contracts" / "AuditSystem.sol"),
    )
    csp = CSPState(
        address="0x7021Fb52487AC1c1733cC47A846dB474B25D01Ab",
        private_key="0x61cabe658a8c206a440bfb65641c9a8a76fcd3915c9e9064fc4763b9e2c4ea83",
        storage_capacity=10**9,
    )
    user1 = build_user(
        "0x24291Ea0B8aB706e1a576beBC869A2b63072f265",
        "0x308539265331010d37c2e16d3b27fcc6a71dff6ffcb26175d4fc2af0e7b36dd8",
        "bench-user-1",
    )
    user2 = build_user(
        "0x2ad9a1698a5309dB005cea681150362Ab99Dc1B3",
        "0x19d737f6b2ac3b146ff985de0dded5b5d11b694f26bb0dd92b0f75c88ad04897",
        "bench-user-2",
    )
    return Runtime(engine=engine, chain=chain, csp=csp, user1=user1, user2=user2, chain_mode=chain_mode_value)


def make_file_bytes(n_blocks: int, block_size: int, dup_ratio: float) -> bytes:
    unique_count = max(1, int(n_blocks * (1.0 - dup_ratio)))
    unique_blocks = []
    for i in range(unique_count):
        random.seed(f"dup-mix-block-{i}")
        unique_blocks.append(bytes(random.getrandbits(8) for _ in range(block_size)))
    all_blocks = [unique_blocks[i % unique_count] for i in range(n_blocks)]
    return b"".join(all_blocks)


def public_indices(n_blocks: int, private_ratio: float) -> List[int]:
    private_count = int(n_blocks * private_ratio)
    private_idx = set(range(private_count))
    return [idx for idx in range(n_blocks) if idx not in private_idx]


def _challenge(engine: CryptoEngine, n_blocks: int, z: int) -> Dict[str, Any]:
    z_value = max(1, min(z, n_blocks))
    seed = f"paper-z-{n_blocks}-{z_value}".encode()
    return {
        "challenge_id": f"chal-paper-{n_blocks}-{z_value}",
        "z": z_value,
        "theta1": engine.H1(b"theta1|" + seed),
        "theta2": engine.H1(b"theta2|" + seed),
    }


def _runtime_meta(rt: Runtime) -> Dict[str, Any]:
    return {
        "chain_mode": rt.chain_mode,
        "chain_backend": rt.chain.backend,
        "pairing_backend": rt.engine.params.pairing_backend,
        "pairing_strict": rt.engine.params.pairing_strict,
        "paper_pairing_backend": "PBC_TYPE_A_NATIVE_PAIRING_APPLY",
        "sector_encryption": "H3_XOR",
        "proof_model": "paper_pbc_local_and_bn254_chain_gas",
        "paper_scale": True,
        "comparable": False,
    }


def _estimate_challenge_bytes(challenge: Dict[str, Any]) -> int:
    # challenge_id, z, theta1, theta2
    return len(challenge["challenge_id"].encode()) + 4 + 32 + 32


def _estimate_proof_bytes(proof: Dict[str, Any]) -> int:
    # Approximated by protocol field sizes instead of Python object memory size.
    payload_hex = proof.get("proof_payload_hex", "")
    payload_bytes = len(payload_hex) // 2 if payload_hex else 0
    return (
        len(proof.get("challenge_id", "").encode())
        + 4 * len(proof.get("indices", []))
        + 32 * len(proof.get("coeffs", []))
        + 32 * len(proof.get("P", []))
        + 32  # sigma_c
        + 32  # Y_agg
        + 32  # checksum-ish scalar
        + payload_bytes
    )


def bench_a_upload(
    block_counts: Sequence[int],
    repeats: int,
    dup_ratio: float,
    private_ratio: float,
) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    rt = build_runtime()
    for n_blocks in block_counts:
        print(f"[A] n_blocks={n_blocks}: running {repeats} rounds...", flush=True)
        tag_samples: List[float] = []
        auth_samples: List[float] = []
        file_bytes = make_file_bytes(n_blocks, rt.engine.params.block_size, dup_ratio)
        blocks = split_file_into_blocks_and_sectors(
            data=file_bytes,
            block_size=rt.engine.params.block_size,
            sectors_per_block=rt.engine.params.sectors_per_block,
        )
        for _ in range(repeats):
            fk, sector_keys = rt.engine.keygen(file_bytes, blocks)
            encrypted_blocks, _ = rt.engine.encrypt_blocks(
                blocks,
                sector_keys,
                public_indices(n_blocks, private_ratio),
                bytes.fromhex(rt.user1.public_key),
            )
            t0 = now_ms()
            _, tags = rt.engine.taggen(encrypted_blocks, fk)
            tag_samples.append(now_ms() - t0)
            t1 = now_ms()
            for i, block in enumerate(encrypted_blocks):
                rt.engine.authgen(block, tags[i], sector_keys[i], gamma=19)
            auth_samples.append(now_ms() - t1)
        rows.append(
            {
                "metric": "A",
                "n_blocks": n_blocks,
                "dup_ratio": dup_ratio,
                "private_ratio": private_ratio,
                "avg_tag_ms": round(avg_ms(tag_samples), 4),
                "avg_auth_ms": round(avg_ms(auth_samples), 4),
            }
        )
    return {"name": "A_upload", "rows": rows, "meta": _runtime_meta(rt)}


def _prepare_uploaded_file(rt: Runtime, n_blocks: int, dup_ratio: float, private_ratio: float) -> Dict[str, Any]:
    file_bytes = make_file_bytes(n_blocks, rt.engine.params.block_size, dup_ratio)
    upload = upload_and_dedup_protocol(
        rt.user1,
        file_bytes,
        rt.csp,
        rt.chain,
        rt.engine,
        public_block_indices=public_indices(n_blocks, private_ratio),
    )
    file_state = rt.csp.files[upload["file_id"]]
    return {"file_bytes": file_bytes, "upload": upload, "file_state": file_state}


def bench_b_prove(challenge_counts: Sequence[int], repeats: int, n_blocks: int, dup_ratio: float, private_ratio: float) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    rt = build_runtime()
    ctx = _prepare_uploaded_file(rt, n_blocks=n_blocks, dup_ratio=dup_ratio, private_ratio=private_ratio)
    file_state = ctx["file_state"]
    for z in challenge_counts:
        print(f"[B] challenge_blocks={z}: running {repeats} rounds...", flush=True)
        samples: List[float] = []
        challenge = _challenge(rt.engine, len(file_state.block_ids), z)
        for _ in range(repeats):
            t0 = now_ms()
            proof_gen(challenge, file_state, rt.csp, rt.engine)
            samples.append(now_ms() - t0)
        rows.append({"metric": "B", "challenge_blocks": z, "avg_prove_ms": round(avg_ms(samples), 4)})
    return {"name": "B_prove", "rows": rows, "meta": _runtime_meta(rt)}


def bench_c_verify(challenge_counts: Sequence[int], repeats: int, n_blocks: int, dup_ratio: float, private_ratio: float) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    rt = build_runtime()
    ctx = _prepare_uploaded_file(rt, n_blocks=n_blocks, dup_ratio=dup_ratio, private_ratio=private_ratio)
    file_state = ctx["file_state"]
    for z in challenge_counts:
        print(f"[C] challenge_blocks={z}: running {repeats} rounds...", flush=True)
        samples: List[float] = []
        challenge = _challenge(rt.engine, len(file_state.block_ids), z)
        if rt.chain.backend == "web3":
            create_audit_request(rt.chain, challenge["challenge_id"], file_state.file_id, rt.user1.address, int(challenge["z"]))
        proof = proof_gen(challenge, file_state, rt.csp, rt.engine)
        for _ in range(repeats):
            t0 = now_ms()
            verify_proof_protocol(proof, challenge, file_state, rt.csp, rt.chain, rt.engine)
            samples.append(now_ms() - t0)
        rows.append(
            {
                "metric": "C",
                "challenge_blocks": z,
                "avg_verify_ms": round(avg_ms(samples), 4),
                "verify_path": "onchain" if rt.chain.backend == "web3" else "local+mock",
            }
        )
    return {"name": "C_verify", "rows": rows, "meta": _runtime_meta(rt)}


def bench_d_encrypt_decrypt(private_ratios: Sequence[float], repeats: int, n_blocks: int, dup_ratio: float) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    rt = build_runtime()
    file_bytes = make_file_bytes(n_blocks, rt.engine.params.block_size, dup_ratio)
    blocks = split_file_into_blocks_and_sectors(
        data=file_bytes,
        block_size=rt.engine.params.block_size,
        sectors_per_block=rt.engine.params.sectors_per_block,
    )
    fk, sector_keys = rt.engine.keygen(file_bytes, blocks)
    _ = fk
    pub_key = bytes.fromhex(rt.user1.public_key)
    for ratio in private_ratios:
        print(f"[D] private_ratio={ratio:.2f}: running {repeats} rounds...", flush=True)
        enc_samples: List[float] = []
        dec_samples: List[float] = []
        public_idx = public_indices(n_blocks, ratio)
        public_idx_set = set(public_idx)
        for _ in range(repeats):
            t0 = now_ms()
            encrypted_blocks, _ = rt.engine.encrypt_blocks(blocks, sector_keys, public_idx, pub_key)
            enc_samples.append(now_ms() - t0)
            t1 = now_ms()
            for i, block in enumerate(encrypted_blocks):
                if i in public_idx_set:
                    continue
                for key, cipher_sector in zip(sector_keys[i], block):
                    rt.engine.s_decrypt(key, cipher_sector)
            dec_samples.append(now_ms() - t1)
        rows.append(
            {
                "metric": "D",
                "private_ratio": ratio,
                "n_blocks": n_blocks,
                "avg_encrypt_ms": round(avg_ms(enc_samples), 4),
                "avg_decrypt_ms": round(avg_ms(dec_samples), 4),
            }
        )
    return {"name": "D_encrypt_decrypt", "rows": rows, "meta": _runtime_meta(rt)}


def bench_e_update(num_updates: int, repeats: int, n_blocks: int, dup_ratio: float, private_ratio: float) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    base_meta: Dict[str, Any] | None = None
    for round_idx in range(repeats):
        print(f"[E] round={round_idx + 1}/{repeats}, updates={num_updates}...", flush=True)
        rt = build_runtime()
        if base_meta is None:
            base_meta = _runtime_meta(rt)
        ctx = _prepare_uploaded_file(rt, n_blocks=n_blocks, dup_ratio=dup_ratio, private_ratio=private_ratio)
        upload = ctx["upload"]
        samples: List[float] = []
        for i in range(num_updates):
            payload = f"update-block-{round_idx}-{i}".encode() * 300
            t0 = now_ms()
            insert_protocol(rt.user1, upload["file_id"], payload, rt.csp, rt.chain, rt.engine, is_public=False)
            samples.append(now_ms() - t0)
        rows.append(
            {
                "metric": "E",
                "round": round_idx + 1,
                "num_updates": num_updates,
                "total_update_ms": round(sum(samples), 4),
                "avg_update_ms": round(avg_ms(samples), 4),
            }
        )
    return {"name": "E_update", "rows": rows, "meta": base_meta or {}}


def bench_f_communication(block_counts: Sequence[int], challenge_counts: Sequence[int], dup_ratio: float, private_ratio: float) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    rt = build_runtime()
    for n_blocks in block_counts:
        print(f"[F] upload communication n_blocks={n_blocks}...", flush=True)
        ctx = _prepare_uploaded_file(rt, n_blocks=n_blocks, dup_ratio=dup_ratio, private_ratio=private_ratio)
        file_state = ctx["file_state"]
        upload = ctx["upload"]
        upload_bytes = len(ctx["file_bytes"])
        for block_id in file_state.block_ids:
            block = rt.csp.blocks[block_id]
            upload_bytes += len(flatten(block["sectors"]))
            if not block["is_public"]:
                upload_bytes += len(rt.csp.key_ciphers[block_id][rt.user1.address])
        rows.append({"metric": "F", "phase": "upload", "n_blocks": n_blocks, "comm_bytes": upload_bytes})

        for z in challenge_counts:
            challenge = _challenge(rt.engine, len(file_state.block_ids), z)
            if rt.chain.backend == "web3":
                create_audit_request(rt.chain, challenge["challenge_id"], file_state.file_id, rt.user1.address, int(challenge["z"]))
            proof = proof_gen(challenge, file_state, rt.csp, rt.engine)
            audit_bytes = _estimate_challenge_bytes(challenge) + _estimate_proof_bytes(proof)
            rows.append({"metric": "F", "phase": "audit", "challenge_blocks": z, "comm_bytes": audit_bytes})
            verify_proof_protocol(proof, challenge, file_state, rt.csp, rt.chain, rt.engine)
            _ = upload
    return {"name": "F_communication", "rows": rows, "meta": _runtime_meta(rt)}


def bench_g_file_dedup(file_blocks: int, private_ratio: float, challenge_blocks: int, dup_ratio: float) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    rt = build_runtime()
    file_bytes = make_file_bytes(file_blocks, rt.engine.params.block_size, dup_ratio)
    blocks = split_file_into_blocks_and_sectors(
        data=file_bytes,
        block_size=rt.engine.params.block_size,
        sectors_per_block=rt.engine.params.sectors_per_block,
    )
    fk, sector_keys = rt.engine.keygen(file_bytes, blocks)
    pub_idx = public_indices(file_blocks, private_ratio)

    t0 = now_ms()
    encrypted_blocks, _ = rt.engine.encrypt_blocks(blocks, sector_keys, pub_idx, bytes.fromhex(rt.user1.public_key))
    encrypt_ms = now_ms() - t0

    t1 = now_ms()
    rt.engine.taggen(encrypted_blocks, fk)
    file_tag_ms = now_ms() - t1

    upload1 = upload_and_dedup_protocol(rt.user1, file_bytes, rt.csp, rt.chain, rt.engine, public_block_indices=pub_idx)
    t2 = now_ms()
    upload2 = upload_and_dedup_protocol(rt.user2, file_bytes, rt.csp, rt.chain, rt.engine, public_block_indices=pub_idx)
    second_upload_ms = now_ms() - t2

    file_state = rt.csp.files[upload1["file_id"]]
    challenge = _challenge(rt.engine, len(file_state.block_ids), challenge_blocks)
    if rt.chain.backend == "web3":
        create_audit_request(rt.chain, challenge["challenge_id"], file_state.file_id, rt.user1.address, int(challenge["z"]))
    t3 = now_ms()
    proof = proof_gen(challenge, file_state, rt.csp, rt.engine)
    prove_ms = now_ms() - t3
    t4 = now_ms()
    verify_ok = verify_proof_protocol(proof, challenge, file_state, rt.csp, rt.chain, rt.engine)
    verify_ms = now_ms() - t4

    rows.append(
        {
            "metric": "G",
            "file_blocks": file_blocks,
            "private_ratio": private_ratio,
            "challenge_blocks": challenge_blocks,
            "file_tag_ms": round(file_tag_ms, 4),
            "encrypt_ms": round(encrypt_ms, 4),
            "prove_ms": round(prove_ms, 4),
            "verify_ms": round(verify_ms, 4),
            "second_upload_ms": round(second_upload_ms, 4),
            "duplicate_detected": bool(upload2["duplicate_file"]),
            "verify_ok": bool(verify_ok),
        }
    )
    return {"name": "G_file_level_dedup", "rows": rows, "meta": _runtime_meta(rt)}


def save_result(result: Dict[str, Any]) -> Dict[str, Path]:
    result_dir = ensure_results_dir()
    csv_path = result_dir / f"{result['name']}.csv"
    json_path = result_dir / f"{result['name']}.json"
    write_csv(csv_path, result["rows"])
    write_json(json_path, result)
    return {"csv": csv_path, "json": json_path}
