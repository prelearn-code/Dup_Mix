from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from typing import Any, Dict, List, Optional, Sequence
from uuid import uuid4

from .chain import create_audit_request, record_update, record_upload, request_transfer, settle_transfer, submit_proof_result
from .crypto import CryptoEngine
from .mht import build_improved_mht, delete_block_mht, insert_block_mht, modify_block_mht
from .models import CSPState, FileState, UserState
from .storage import block_level_dedup_check, file_level_dedup_check, store_authenticator, store_key_cipher, store_upload_metadata, update_ownership_record
from .utils import compressed_public_key_from_private, flatten_block, sha256_hex, split_file_into_blocks_and_sectors


def _normalize_private_key(private_key: str) -> bytes:
    return bytes.fromhex(private_key[2:] if private_key.startswith("0x") else private_key)

# 权限检查：确保用户是文件当前所有者，才能执行动态插入/修改/删除等操作
def _owner_guard(user: UserState, csp_state: CSPState, file_id: str) -> None:
    if csp_state.ownership.get(file_id) != user.address:
        raise PermissionError("User is not the current owner of the file.")

# 计算用户公钥：优先使用 user.public_key，兼容性考虑 fallback 到 private_key 计算压缩公钥
def _resolve_public_key(user: UserState) -> bytes:
    public_key_hex = user.public_key or compressed_public_key_from_private(user.private_key)
    return bytes.fromhex(public_key_hex[2:] if public_key_hex.startswith("0x") else public_key_hex)

# 计算块内每个扇区的 H1 值，作为后续 tag/authenticator 计算的基础
def _compute_sector_values(engine: CryptoEngine, block: Sequence[bytes]) -> List[int]:
    return [engine.H1(sector) for sector in block]


def _build_file_state(
    owner: UserState,
    file_bytes: bytes,
    t: int,
    block_ids: List[str],
    tags: List[int],
    public_blocks: Sequence[int],
    metadata: Dict[str, Any],
) -> FileState:
    file_id = metadata.get("file_id", f"file-{uuid4().hex[:12]}")
    return FileState(
        file_id=file_id,
        owner_address=owner.address,
        file_size=len(file_bytes),
        file_hash=sha256_hex(file_bytes),
        t=f"{t:064x}",
        block_ids=block_ids,
        block_tags=[f"{tag:064x}" for tag in tags],
        public_blocks=set(public_blocks),
        is_deduplicated=metadata.get("is_deduplicated", False),
        mht_root=metadata.get("mht_root", ""),
        metadata=metadata,
    )

# 准备块级记录的公共函数，包含 tag/sectors/sector_values/is_public/owners/sector_keys 等信息，供上传和动态插入流程使用
def _prepare_block_record(engine: CryptoEngine, block: Sequence[bytes], is_public: bool, tag: int, sector_keys: Sequence[int]) -> Dict[str, Any]:
    return {
        "tag": f"{tag:064x}",
        "sectors": [bytes(sector) for sector in block],
        "sector_values": _compute_sector_values(engine, block),
        "is_public": is_public,
        "owners": set(),
        "sector_keys": list(sector_keys),
    }

# 上传与去重流程：用户生成加密块和标签，CSP 验证身份后进行文件级和块级去重，生成认证器并存储元数据，最后链上记录 upload 事件。
def upload_and_dedup_protocol(
    owner: UserState,
    file_bytes: bytes,
    csp_state: CSPState,
    chain_state: Any,
    engine: CryptoEngine,
    public_block_indices: Optional[Sequence[int]] = None,
    gamma: int = 19,
) -> Dict[str, Any]:
    """上传与去重流程。

    对应论文流程：用户 KeyGen/Encrypt/TagGen -> 生成 UID/W -> CSP 验证身份 ->
    文件级/块级去重 -> AuthGen/认证器验证 -> CSP 存储元数据 -> 链上记录 upload。
    """
    public_block_indices = list(public_block_indices or [])
    blocks = split_file_into_blocks_and_sectors(
        data=file_bytes,
        block_size=engine.params.block_size,
        sectors_per_block=engine.params.sectors_per_block,
    )
    fk, sector_keys = engine.keygen(file_bytes, blocks)
    encrypted_blocks, key_cipher_map = engine.encrypt_blocks(blocks, sector_keys, public_block_indices, _resolve_public_key(owner))
    t, tags = engine.taggen(encrypted_blocks, fk)
    mu, UID, W = engine.generate_user_identity(owner.uid, t)
    owner.mu, owner.UID, owner.W = mu, UID, W
    if not engine.verify_user_identity(owner.uid, t, UID, W):
        raise ValueError("User identity verification failed.")

    tag_hexes = [f"{tag:064x}" for tag in tags]
    duplicate_file = file_level_dedup_check(csp_state, f"{t:064x}")

    if duplicate_file:
        existing_file = csp_state.files[csp_state.file_index[f"{t:064x}"]]
        for index, block_id in enumerate(existing_file.block_ids):
            csp_state.blocks[block_id]["owners"].add(owner.address)
            if index not in public_block_indices:
                store_key_cipher(csp_state, block_id, owner.address, key_cipher_map[index])
        metadata = {
            "file_id": f"file-{uuid4().hex[:12]}",
            "mht_root": existing_file.mht_root,
            "tree": deepcopy(existing_file.metadata["tree"]),
            "fk": fk,
            "gamma": gamma,
            "is_deduplicated": True,
        }
        file_state = _build_file_state(owner, file_bytes, t, list(existing_file.block_ids), tags, public_block_indices, metadata)
        store_upload_metadata(csp_state, file_state)
        record_upload(chain_state, file_state.file_id, owner.address, file_state.t, file_state.mht_root)
        owner.local_files[file_state.file_id] = {"fk": fk, "sector_keys": sector_keys, "gamma": gamma, "t": t, "UID": UID, "W": W}
        return {"file_id": file_state.file_id, "t": file_state.t, "UID": UID, "W": W, "duplicate_file": True, "block_ids": list(existing_file.block_ids)}

    block_ids: List[str] = []
    unique_indices = set(block_level_dedup_check(csp_state, tag_hexes))
    per_block_auth: Dict[int, Dict[str, int]] = {}
    for index, block in enumerate(encrypted_blocks):
        tag_hex = tag_hexes[index]
        if tag_hex in csp_state.block_index:
            block_id = csp_state.block_index[tag_hex]
            csp_state.blocks[block_id]["owners"].add(owner.address)
            if index not in public_block_indices:
                store_key_cipher(csp_state, block_id, owner.address, key_cipher_map[index])
            block_ids.append(block_id)
            continue
        block_id = f"blk-{uuid4().hex[:12]}"
        y_i, Y_i, sigma_i = engine.authgen(block, tags[index], sector_keys[index], gamma)
        if not engine.verify_upload_authenticator(block, tags[index], Y_i, sigma_i):
            raise ValueError("Upload authenticator verification failed.")
        record = _prepare_block_record(engine, block, index in public_block_indices, tags[index], sector_keys[index])
        record["owners"].add(owner.address)
        csp_state.blocks[block_id] = record
        csp_state.block_index[tag_hex] = block_id
        store_authenticator(csp_state, block_id, sigma_i, y_i, Y_i)
        if index not in public_block_indices:
            store_key_cipher(csp_state, block_id, owner.address, key_cipher_map[index])
        per_block_auth[index] = {"sigma": sigma_i, "Y": Y_i, "y": y_i}
        block_ids.append(block_id)

    tree, root = build_improved_mht(tag_hexes)
    metadata = {
        "file_id": f"file-{uuid4().hex[:12]}",
        "tree": tree,
        "mht_root": root,
        "fk": fk,
        "gamma": gamma,
        "is_deduplicated": bool(unique_indices) and len(unique_indices) != len(tags),
    }
    file_state = _build_file_state(owner, file_bytes, t, block_ids, tags, public_block_indices, metadata)
    file_state.mht_root = root
    store_upload_metadata(csp_state, file_state)
    record_upload(chain_state, file_state.file_id, owner.address, file_state.t, root)
    owner.local_files[file_state.file_id] = {"fk": fk, "sector_keys": sector_keys, "gamma": gamma, "t": t, "UID": UID, "W": W, "public_blocks": list(public_block_indices)}
    return {"file_id": file_state.file_id, "t": file_state.t, "UID": UID, "W": W, "duplicate_file": False, "block_ids": block_ids, "root": root, "per_block_auth": per_block_auth}


def audit_req(
    req: str,
    n: int,
    engine: CryptoEngine,
    chain_state: Any | None = None,
    requester: str = "auditor",
    z_value: Optional[int] = None,
) -> Dict[str, Any]:
    """AuditReq 流程：生成 Chal=(z, theta1, theta2)，并把 challenge 请求写入链状态。"""
    z_input = n if z_value is None else z_value
    z_value = min(max(1, int(z_input)), n)
    theta1 = engine.H1(f"theta1|{req}|{uuid4().hex}".encode())
    theta2 = engine.H1(f"theta2|{req}|{uuid4().hex}".encode())
    challenge = {"challenge_id": f"chal-{uuid4().hex[:12]}", "z": z_value, "theta1": theta1, "theta2": theta2}
    if chain_state is not None:
        create_audit_request(chain_state, challenge["challenge_id"], req, requester, z_value)
    return challenge


def proof_gen(challenge: Dict[str, Any], file_state: FileState, csp_state: CSPState, engine: CryptoEngine) -> Dict[str, Any]:
    """ProofGen 流程。

    对应论文公式：x_i=f1(theta1,i)，v_i=f2(theta2,i)，
    P_j=sum_i v_i*c_{x_i,j}，sigma_c=prod_i sigma_{x_i}^{v_i}。
    """
    n_blocks = len(file_state.block_ids)
    indices = [engine.f1(i, challenge["theta1"], n_blocks) for i in range(challenge["z"])]
    coeffs = [engine.f2(i, challenge["theta2"]) for i in range(challenge["z"])]
    sector_count = engine.params.sectors_per_block
    P_values = [0 for _ in range(sector_count)]
    sigma_store: Dict[int, int] = {}
    y_store: Dict[int, int] = {}
    base_store: Dict[int, int] = {}
    for pos, (block_index, coeff) in enumerate(zip(indices, coeffs)):
        block_id = file_state.block_ids[block_index]
        block = csp_state.blocks[block_id]
        sigma_store[pos] = csp_state.authenticators[block_id]["sigma"]
        y_store[pos] = csp_state.authenticators[block_id]["Y"]
        base = engine.H2(engine.s_param + int.to_bytes(int(file_state.block_tags[block_index], 16), 32, "big"))
        for r_j, value in zip(engine.r_values, block["sector_values"]):
            base = (base + (r_j * value)) % engine.q
        base_store[pos] = base
        for sector_idx, value in enumerate(block["sector_values"]):
            P_values[sector_idx] = (P_values[sector_idx] + coeff * value) % engine.q
    sigma_c = engine.aggregate_authenticator(range(len(indices)), coeffs, sigma_store)
    pairing_rhs = sum((coeff * engine.pairing_exponent(base_store[idx], y_store[idx])) % engine.q for idx, coeff in enumerate(coeffs)) % engine.q
    # Deterministic payload and checksum used by real-chain benchmark path.
    payload_lines = [
        challenge["challenge_id"],
        ",".join(str(i) for i in indices),
        ",".join(str(c) for c in coeffs),
        ",".join(str(v) for v in P_values),
        str(sigma_c),
        str(pairing_rhs),
    ]
    payload = "|".join(payload_lines).encode()
    checksum = sum((idx + 1) * b for idx, b in enumerate(payload)) % engine.q
    return {
        "challenge_id": challenge["challenge_id"],
        "indices": indices,
        "coeffs": coeffs,
        "P": P_values,
        "sigma_c": sigma_c,
        "pairing_rhs": pairing_rhs,
        "proof_payload_hex": payload.hex(),
        "proof_digest_hex": sha256(payload).hexdigest(),
        "proof_checksum": checksum,
        "schema_version": "v2",
    }


def verify_proof_protocol(
    proof: Dict[str, Any],
    challenge: Dict[str, Any],
    file_state: FileState,
    csp_state: CSPState,
    chain_state: Any,
    engine: CryptoEngine,
) -> bool:
    """VerifyProof 流程。

    重算 x_i/v_i/P_j/sigma_c，并验证论文审计 pairing 公式：
    e(sigma_c,g)==prod_i e(H2(s||tg_i)*prod_j r_j^{c_i,j},Y_i)^{v_i}。
    """
    expected_indices = [engine.f1(i, challenge["theta1"], len(file_state.block_ids)) for i in range(challenge["z"])]
    expected_coeffs = [engine.f2(i, challenge["theta2"]) for i in range(challenge["z"])]
    expected_P = [0 for _ in range(engine.params.sectors_per_block)]
    sigma_store: Dict[int, int] = {}
    base_values: List[int] = []
    y_values: List[int] = []
    pairing_rhs = 0
    for pos, (block_index, coeff) in enumerate(zip(expected_indices, expected_coeffs)):
        block_id = file_state.block_ids[block_index]
        block = csp_state.blocks[block_id]
        sigma_i = csp_state.authenticators[block_id]["sigma"]
        Y_i = csp_state.authenticators[block_id]["Y"]
        base_i = engine.H2(engine.s_param + int.to_bytes(int(file_state.block_tags[block_index], 16), 32, "big"))
        for r_j, value in zip(engine.r_values, block["sector_values"]):
            base_i = (base_i + (r_j * value)) % engine.q
        base_values.append(base_i)
        y_values.append(Y_i)
        pairing_rhs = (pairing_rhs + (coeff * engine.pairing_exponent(base_i, Y_i))) % engine.q
        for sector_idx, value in enumerate(block["sector_values"]):
            expected_P[sector_idx] = (expected_P[sector_idx] + coeff * value) % engine.q
        sigma_store[pos] = sigma_i

    expected_sigma = engine.aggregate_authenticator(range(len(expected_indices)), expected_coeffs, sigma_store)
    local_valid = proof["indices"] == expected_indices and proof["coeffs"] == expected_coeffs and proof["P"] == expected_P
    local_valid = local_valid and engine.pairing_equal(proof["sigma_c"], engine.g, expected_sigma, engine.g)
    local_valid = local_valid and engine.pairing_product_equal(proof["sigma_c"], base_values, y_values, expected_coeffs)
    local_valid = local_valid and (proof.get("pairing_rhs") == pairing_rhs)
    chain_result = submit_proof_result(
        chain_state,
        challenge["challenge_id"],
        file_state.file_id,
        file_state.owner_address,
        csp_state.address,
        local_valid,
        proof_payload_hex=proof.get("proof_payload_hex", ""),
        proof_checksum=int(proof.get("proof_checksum", 0)),
    )
    valid = bool(chain_result.get("is_valid", local_valid))
    csp_state.audit_history.append({"challenge": challenge, "proof": proof, "valid": valid, "chain_result": chain_result})
    return valid


def retrieve_protocol(user: UserState, file_id: str, csp_state: CSPState, engine: CryptoEngine, UID: bytes, W: bytes) -> bytes:
    """数据取回流程。

    CSP 先验证 owner 和 UID/W；用户解封装 {k_i,j} 后，对 private sector 执行
    m_i,j=H3(k_i,j) xor c_i,j，并按原始 file_size 去除 padding。
    """
    file_state = csp_state.files[file_id]
    _owner_guard(user, csp_state, file_id)
    t_int = int(file_state.t, 16)
    if not engine.verify_user_identity(user.uid, t_int, UID, W):
        raise PermissionError("Invalid UID/W provided.")
    recovered_blocks: List[List[bytes]] = []
    private_key = _normalize_private_key(user.private_key)
    for block_id in file_state.block_ids:
        block = csp_state.blocks[block_id]
        if block["is_public"]:
            recovered_blocks.append(block["sectors"])
            continue
        key_cipher = csp_state.key_ciphers.get(block_id, {}).get(user.address)
        if key_cipher is None:
            raise PermissionError("No key cipher available for this user.")
        key_list = engine.k_decrypt(private_key, key_cipher)
        if len(key_list) != len(block["sectors"]):
            raise PermissionError("Wrong secret key material.")
        decrypted = [engine.s_decrypt(key, sector) for key, sector in zip(key_list, block["sectors"])]
        recovered_blocks.append(decrypted)
    return b"".join(flatten_block(block) for block in recovered_blocks)[: file_state.file_size]


def insert_protocol(
    user: UserState,
    file_id: str,
    new_block_bytes: bytes,
    csp_state: CSPState,
    chain_state: Any,
    engine: CryptoEngine,
    index: Optional[int] = None,
    is_public: bool = False,
) -> Dict[str, Any]:
    """动态插入流程：生成新块 tag/authenticator，插入 MHT/AVT，并链上记录新 root。"""
    _owner_guard(user, csp_state, file_id)
    file_state = csp_state.files[file_id]
    gamma = user.local_files[file_id]["gamma"]
    block = split_file_into_blocks_and_sectors(data=new_block_bytes, block_size=engine.params.block_size, sectors_per_block=engine.params.sectors_per_block)[0]
    keys = [engine.s_keygen(sector) for sector in block]
    encrypted_block = list(block) if is_public else [engine.s_encrypt(key, sector) for key, sector in zip(keys, block)]
    tag = engine.H1(flatten_block(encrypted_block))
    tag_hex = f"{tag:064x}"
    insert_at = len(file_state.block_ids) if index is None else index
    if tag_hex in csp_state.block_index:
        block_id = csp_state.block_index[tag_hex]
        csp_state.blocks[block_id]["owners"].add(user.address)
        if not is_public:
            store_key_cipher(csp_state, block_id, user.address, engine.k_encrypt(_resolve_public_key(user), keys))
    else:
        block_id = f"blk-{uuid4().hex[:12]}"
        y_i, Y_i, sigma_i = engine.authgen(encrypted_block, tag, keys, gamma)
        record = _prepare_block_record(engine, encrypted_block, is_public, tag, keys)
        record["owners"].add(user.address)
        csp_state.blocks[block_id] = record
        csp_state.block_index[tag_hex] = block_id
        store_authenticator(csp_state, block_id, sigma_i, y_i, Y_i)
        if not is_public:
            store_key_cipher(csp_state, block_id, user.address, engine.k_encrypt(_resolve_public_key(user), keys))
    file_state.block_ids.insert(insert_at, block_id)
    file_state.block_tags.insert(insert_at, tag_hex)
    if is_public:
        file_state.public_blocks.add(insert_at)
    tree, root = insert_block_mht(file_state.metadata["tree"], tag_hex, insert_at)
    file_state.metadata["tree"] = tree
    file_state.mht_root = root
    file_state.metadata["mht_root"] = root
    record_update(chain_state, file_id, root, "insert")
    return {"file_id": file_id, "root": root, "op": "insert"}


def modify_protocol(
    user: UserState,
    file_id: str,
    block_index: int,
    new_block_bytes: bytes,
    csp_state: CSPState,
    chain_state: Any,
    engine: CryptoEngine,
    is_public: bool = False,
) -> Dict[str, Any]:
    """动态修改流程：替换目标块、重新生成 tag/authenticator，更新 MHT/AVT root 并上链。"""
    _owner_guard(user, csp_state, file_id)
    file_state = csp_state.files[file_id]
    gamma = user.local_files[file_id]["gamma"]
    old_block_id = file_state.block_ids[block_index]
    csp_state.blocks[old_block_id]["owners"].discard(user.address)
    block = split_file_into_blocks_and_sectors(data=new_block_bytes, block_size=engine.params.block_size, sectors_per_block=engine.params.sectors_per_block)[0]
    keys = [engine.s_keygen(sector) for sector in block]
    encrypted_block = list(block) if is_public else [engine.s_encrypt(key, sector) for key, sector in zip(keys, block)]
    tag = engine.H1(flatten_block(encrypted_block))
    tag_hex = f"{tag:064x}"
    if tag_hex in csp_state.block_index:
        new_block_id = csp_state.block_index[tag_hex]
        csp_state.blocks[new_block_id]["owners"].add(user.address)
        if not is_public:
            store_key_cipher(csp_state, new_block_id, user.address, engine.k_encrypt(_resolve_public_key(user), keys))
    else:
        new_block_id = f"blk-{uuid4().hex[:12]}"
        y_i, Y_i, sigma_i = engine.authgen(encrypted_block, tag, keys, gamma)
        record = _prepare_block_record(engine, encrypted_block, is_public, tag, keys)
        record["owners"].add(user.address)
        csp_state.blocks[new_block_id] = record
        csp_state.block_index[tag_hex] = new_block_id
        store_authenticator(csp_state, new_block_id, sigma_i, y_i, Y_i)
        if not is_public:
            store_key_cipher(csp_state, new_block_id, user.address, engine.k_encrypt(_resolve_public_key(user), keys))
    file_state.block_ids[block_index] = new_block_id
    file_state.block_tags[block_index] = tag_hex
    tree, root = modify_block_mht(file_state.metadata["tree"], block_index, tag_hex)
    file_state.metadata["tree"] = tree
    file_state.mht_root = root
    file_state.metadata["mht_root"] = root
    record_update(chain_state, file_id, root, "modify")
    return {"file_id": file_id, "root": root, "op": "modify"}


def delete_protocol(user: UserState, file_id: str, block_index: int, csp_state: CSPState, chain_state: Any, engine: CryptoEngine) -> Dict[str, Any]:
    """动态删除流程：删除目标块 tag，更新 MHT/AVT root，并链上记录删除操作。"""
    _owner_guard(user, csp_state, file_id)
    file_state = csp_state.files[file_id]
    block_id = file_state.block_ids.pop(block_index)
    file_state.block_tags.pop(block_index)
    csp_state.blocks[block_id]["owners"].discard(user.address)
    if block_index in file_state.public_blocks:
        file_state.public_blocks.remove(block_index)
    tree, root = delete_block_mht(file_state.metadata["tree"], block_index)
    file_state.metadata["tree"] = tree
    file_state.mht_root = root
    file_state.metadata["mht_root"] = root
    record_update(chain_state, file_id, root, "delete")
    return {"file_id": file_id, "root": root, "op": "delete"}


def ownership_transfer_protocol(from_user: UserState, to_user: UserState, file_id: str, csp_state: CSPState, chain_state: Any, engine: CryptoEngine) -> Dict[str, Any]:
    """权限转让流程。

    对应论文 transfer 阶段：买方请求转让，旧 owner 通过取回证明可访问，
    CSP 将 private block keys 重新封装给新 owner，更新 ownership，新 owner 取回验证后链上结算。
    """
    _owner_guard(from_user, csp_state, file_id)
    file_state = csp_state.files[file_id]
    request_transfer(chain_state, file_id, from_user.address, to_user.address)
    original_bytes = retrieve_protocol(from_user, file_id, csp_state, engine, from_user.UID, from_user.W)
    for block_id in file_state.block_ids:
        block = csp_state.blocks[block_id]
        block["owners"].discard(from_user.address)
        block["owners"].add(to_user.address)
        if not block["is_public"]:
            keys = list(block["sector_keys"])
            key_cipher = engine.k_encrypt(_resolve_public_key(to_user), keys)
            store_key_cipher(csp_state, block_id, to_user.address, key_cipher)
            csp_state.key_ciphers[block_id].pop(from_user.address, None)
    to_mu, to_UID, to_W = engine.generate_user_identity(to_user.uid, int(file_state.t, 16))
    to_user.mu, to_user.UID, to_user.W = to_mu, to_UID, to_W
    update_ownership_record(csp_state, file_id, to_user.address)
    to_user.local_files[file_id] = deepcopy(from_user.local_files[file_id])
    retrieved = retrieve_protocol(to_user, file_id, csp_state, engine, to_UID, to_W)
    success = retrieved == original_bytes
    settle_transfer(chain_state, file_id, success)
    return {"file_id": file_id, "success": success, "new_owner": to_user.address, "old_owner": from_user.address}
