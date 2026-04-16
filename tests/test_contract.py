from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.chain import connect_chain, create_audit_request, deploy_contract, record_update, record_upload, request_transfer, settle_transfer, submit_proof_result


def test_contract_lifecycle():
    chain = deploy_contract(connect_chain(chain_id=1337, force_mock=True), str(ROOT / "contracts" / "AuditSystem.sol"))
    assert chain.contract_address

    upload = record_upload(chain, "file-1", "0xowner", "ttag", "root0")
    assert upload["root"] == "root0"
    assert chain.uploads["file-1"]["owner"] == "0xowner"

    challenge = create_audit_request(chain, "chal-1", "file-1", "0xowner", 2)
    assert challenge["z"] == 2

    result = submit_proof_result(chain, "chal-1", "file-1", "0xowner", "0xcsp", True)
    assert result["is_valid"] is True
    assert chain.proof_results["chal-1"]["is_valid"] is True

    update = record_update(chain, "file-1", "root1", "modify")
    assert update["root"] == "root1"
    assert chain.uploads["file-1"]["root"] == "root1"

    request = request_transfer(chain, "file-1", "0xowner", "0xnew", 9)
    assert request["status"] == "requested"
    settled = settle_transfer(chain, "file-1", True)
    assert settled["status"] == "settled-success"
