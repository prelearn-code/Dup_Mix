from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.chain import connect_chain, deploy_contract
from src.crypto import CryptoEngine, setup
from src.models import CSPState, UserState
from src.protocol import audit_req, proof_gen, retrieve_protocol, upload_and_dedup_protocol, verify_proof_protocol
from src.utils import compressed_public_key_from_private, load_environment


def build_user(address: str, private_key: str, uid: str) -> UserState:
    return UserState(address=address, private_key=private_key, uid=uid, public_key=compressed_public_key_from_private(private_key))


def main() -> None:
    load_environment()
    params = setup(sectors_per_block=128, s=b"demo-secret")
    engine = CryptoEngine(params)
    chain = deploy_contract(connect_chain(chain_id=1337, force_mock=True), str(ROOT / "contracts" / "AuditSystem.sol"))
    user = build_user("0x24291Ea0B8aB706e1a576beBC869A2b63072f265", "0x308539265331010d37c2e16d3b27fcc6a71dff6ffcb26175d4fc2af0e7b36dd8", "user1-demo")
    csp = CSPState(address="0x7021Fb52487AC1c1733cC47A846dB474B25D01Ab", private_key="0x61cabe658a8c206a440bfb65641c9a8a76fcd3915c9e9064fc4763b9e2c4ea83", storage_capacity=10**9)

    file_bytes = (b"public-block" * 256) + (b"private-block" * 256)
    upload = upload_and_dedup_protocol(user, file_bytes, csp, chain, engine, public_block_indices=[0])
    file_state = csp.files[upload["file_id"]]
    challenge = audit_req(upload["file_id"], len(file_state.block_ids), engine, chain_state=chain, requester=user.address)
    proof = proof_gen(challenge, file_state, csp, engine)
    verified = verify_proof_protocol(proof, challenge, file_state, csp, chain, engine)
    recovered = retrieve_protocol(user, upload["file_id"], csp, engine, upload["UID"], upload["W"])

    print(f"file_id={upload['file_id']}")
    print(f"audit_verified={verified}")
    print(f"retrieve_match={recovered == file_bytes}")


if __name__ == "__main__":
    main()
