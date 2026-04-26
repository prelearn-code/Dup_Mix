from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.chain import connect_chain, deploy_contract
from src.crypto import CryptoEngine, setup
from src.local_client_store import load_upload_record, save_upload_record, save_user_profile
from src.local_csp_store import load_csp_state, save_csp_state
from src.models import CSPState, UserState
from src.protocol import retrieve_protocol, upload_and_dedup_protocol
from src.utils import compressed_public_key_from_private


OWNER_PRIVATE_KEY = "0x308539265331010d37c2e16d3b27fcc6a71dff6ffcb26175d4fc2af0e7b36dd8"
CSP_PRIVATE_KEY = "0x61cabe658a8c206a440bfb65641c9a8a76fcd3915c9e9064fc4763b9e2c4ea83"


def _owner() -> UserState:
    return UserState(
        address="0x24291Ea0B8aB706e1a576beBC869A2b63072f265",
        private_key=OWNER_PRIVATE_KEY,
        uid="store-owner",
        public_key=compressed_public_key_from_private(OWNER_PRIVATE_KEY),
    )


def test_structured_csp_and_client_stores_roundtrip(tmp_path: Path):
    csp_db = tmp_path / "csp_db"
    client_db = tmp_path / "client_db"
    source = tmp_path / "client-file.bin"
    file_bytes = (b"local-store-roundtrip|" * 700)[:9000]
    source.write_bytes(file_bytes)

    owner = _owner()
    csp = CSPState(
        address="0x7021Fb52487AC1c1733cC47A846dB474B25D01Ab",
        private_key=CSP_PRIVATE_KEY,
        storage_capacity=10**9,
    )
    engine = CryptoEngine(setup(sectors_per_block=128, s=b"local-store-test"))
    chain = deploy_contract(connect_chain(force_mock=True), str(ROOT / "contracts" / "AuditSystem.sol"))

    upload = upload_and_dedup_protocol(owner, file_bytes, csp, chain, engine, public_block_indices=[0])
    file_state = csp.files[upload["file_id"]]

    save_csp_state(csp, csp_db)
    save_user_profile(client_db, owner)
    save_upload_record(client_db, owner, source, upload, file_state, chain.uploads.get(upload["file_id"], {}))

    loaded = load_csp_state(csp_db, csp.address, csp.private_key, csp.storage_capacity)
    record = load_upload_record(client_db, upload["file_id"])

    assert loaded.file_index[file_state.t] == file_state.file_id
    assert loaded.ownership[file_state.file_id] == owner.address
    assert len(loaded.blocks) == len(csp.blocks)
    assert len(loaded.authenticators) == len(csp.authenticators)
    assert record["file_hash"] == file_state.file_hash

    recovered = retrieve_protocol(owner, upload["file_id"], loaded, engine, owner.UID, owner.W)
    assert recovered == file_bytes
