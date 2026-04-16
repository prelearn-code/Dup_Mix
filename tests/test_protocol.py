from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.chain import connect_chain, deploy_contract
from src.crypto import CryptoEngine, setup
from src.models import CSPState, UserState
from src.protocol import audit_req, delete_protocol, insert_protocol, modify_protocol, ownership_transfer_protocol, proof_gen, retrieve_protocol, upload_and_dedup_protocol, verify_proof_protocol
from src.utils import compressed_public_key_from_private


def build_user(address: str, private_key: str, uid: str) -> UserState:
    return UserState(address=address, private_key=private_key, uid=uid, public_key=compressed_public_key_from_private(private_key))


@pytest.fixture()
def runtime():
    params = setup(sectors_per_block=128, s=b"test-secret")
    engine = CryptoEngine(params)
    chain = deploy_contract(connect_chain(chain_id=1337, force_mock=True), str(ROOT / "contracts" / "AuditSystem.sol"))
    csp = CSPState(address="0x7021Fb52487AC1c1733cC47A846dB474B25D01Ab", private_key="0x61cabe658a8c206a440bfb65641c9a8a76fcd3915c9e9064fc4763b9e2c4ea83", storage_capacity=10**9)
    user1 = build_user("0x24291Ea0B8aB706e1a576beBC869A2b63072f265", "0x308539265331010d37c2e16d3b27fcc6a71dff6ffcb26175d4fc2af0e7b36dd8", "user1-test")
    user2 = build_user("0x2ad9a1698a5309dB005cea681150362Ab99Dc1B3", "0x19d737f6b2ac3b146ff985de0dded5b5d11b694f26bb0dd92b0f75c88ad04897", "user2-test")
    return engine, chain, csp, user1, user2


def test_protocol_end_to_end(runtime):
    engine, chain, csp, user1, user2 = runtime
    file_bytes = (b"A" * 4096) + (b"B" * 4096)

    upload = upload_and_dedup_protocol(user1, file_bytes, csp, chain, engine, public_block_indices=[0])
    assert upload["file_id"] in csp.files
    assert engine.verify_user_identity(user1.uid, int(upload["t"], 16), upload["UID"], upload["W"])

    challenge = audit_req(upload["file_id"], len(csp.files[upload["file_id"]].block_ids), engine, chain_state=chain, requester=user1.address)
    proof = proof_gen(challenge, csp.files[upload["file_id"]], csp, engine)
    assert verify_proof_protocol(proof, challenge, csp.files[upload["file_id"]], csp, chain, engine)

    recovered = retrieve_protocol(user1, upload["file_id"], csp, engine, upload["UID"], upload["W"])
    assert recovered == file_bytes

    insert_protocol(user1, upload["file_id"], b"INSERT" * 600, csp, chain, engine, is_public=False)
    modify_protocol(user1, upload["file_id"], 0, b"MODIFY" * 600, csp, chain, engine, is_public=True)
    delete_protocol(user1, upload["file_id"], 1, csp, chain, engine)

    transfer = ownership_transfer_protocol(user1, user2, upload["file_id"], csp, chain, engine)
    assert transfer["success"] is True

    recovered_by_user2 = retrieve_protocol(user2, upload["file_id"], csp, engine, user2.UID, user2.W)
    assert len(recovered_by_user2) > 0

    with pytest.raises(PermissionError):
        retrieve_protocol(user1, upload["file_id"], csp, engine, upload["UID"], upload["W"])


def test_protocol_failures(runtime):
    engine, chain, csp, user1, _ = runtime
    file_bytes = (b"C" * 4096) + (b"D" * 4096)
    upload = upload_and_dedup_protocol(user1, file_bytes, csp, chain, engine, public_block_indices=[0])
    file_state = csp.files[upload["file_id"]]
    challenge = audit_req(upload["file_id"], len(file_state.block_ids), engine, chain_state=chain, requester=user1.address)
    proof = proof_gen(challenge, file_state, csp, engine)

    wrong_uid = b"\x00" * 32
    with pytest.raises(PermissionError):
        retrieve_protocol(user1, upload["file_id"], csp, engine, wrong_uid, upload["W"])

    wrong_user = UserState(address=user1.address, private_key="0x" + "11" * 32, uid=user1.uid, public_key=compressed_public_key_from_private("0x" + "11" * 32))
    with pytest.raises(Exception):
        retrieve_protocol(wrong_user, upload["file_id"], csp, engine, upload["UID"], upload["W"])

    tampered_proof = dict(proof)
    tampered_proof["P"] = list(proof["P"])
    tampered_proof["P"][0] = (tampered_proof["P"][0] + 1) % engine.q
    assert not verify_proof_protocol(tampered_proof, challenge, file_state, csp, chain, engine)

    block_id = file_state.block_ids[0]
    csp.authenticators[block_id]["sigma"] = (csp.authenticators[block_id]["sigma"] + 12345) % engine.q
    tampered = proof_gen(challenge, file_state, csp, engine)
    tampered["sigma_c"] = (tampered["sigma_c"] + 1) % engine.q
    assert not verify_proof_protocol(tampered, challenge, file_state, csp, chain, engine)
