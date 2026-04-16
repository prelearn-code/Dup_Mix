from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.chain import connect_chain, deploy_contract
from src.crypto import CryptoEngine, setup
from src.models import CSPState, UserState
from src.protocol import delete_protocol, insert_protocol, modify_protocol, ownership_transfer_protocol, retrieve_protocol, upload_and_dedup_protocol
from src.utils import compressed_public_key_from_private, load_environment


def build_user(address: str, private_key: str, uid: str) -> UserState:
    return UserState(address=address, private_key=private_key, uid=uid, public_key=compressed_public_key_from_private(private_key))


def main() -> None:
    load_environment()
    params = setup(sectors_per_block=128, s=b"demo-secret")
    engine = CryptoEngine(params)
    chain = deploy_contract(connect_chain(chain_id=1337, force_mock=True), str(ROOT / "contracts" / "AuditSystem.sol"))
    csp = CSPState(address="0x7021Fb52487AC1c1733cC47A846dB474B25D01Ab", private_key="0x61cabe658a8c206a440bfb65641c9a8a76fcd3915c9e9064fc4763b9e2c4ea83", storage_capacity=10**9)
    user1 = build_user("0x24291Ea0B8aB706e1a576beBC869A2b63072f265", "0x308539265331010d37c2e16d3b27fcc6a71dff6ffcb26175d4fc2af0e7b36dd8", "user1-demo")
    user2 = build_user("0x2ad9a1698a5309dB005cea681150362Ab99Dc1B3", "0x19d737f6b2ac3b146ff985de0dded5b5d11b694f26bb0dd92b0f75c88ad04897", "user2-demo")

    file_bytes = (b"alpha" * 900) + (b"beta" * 900)
    upload = upload_and_dedup_protocol(user1, file_bytes, csp, chain, engine, public_block_indices=[0])
    insert_protocol(user1, upload["file_id"], b"inserted-block" * 200, csp, chain, engine, is_public=False)
    modify_protocol(user1, upload["file_id"], 0, b"modified-public" * 180, csp, chain, engine, is_public=True)
    delete_protocol(user1, upload["file_id"], 1, csp, chain, engine)
    transfer = ownership_transfer_protocol(user1, user2, upload["file_id"], csp, chain, engine)
    recovered = retrieve_protocol(user2, upload["file_id"], csp, engine, user2.UID, user2.W)

    print(f"transfer_success={transfer['success']}")
    print(f"new_owner={transfer['new_owner']}")
    print(f"retrieved_bytes={len(recovered)}")


if __name__ == "__main__":
    main()
