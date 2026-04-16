from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .models import ChainState
from .utils import logger

try:
    from web3 import HTTPProvider, Web3
except Exception:
    HTTPProvider = None
    Web3 = None


def connect_chain(
    rpc_url: Optional[str] = None,
    chain_id: int = 1337,
    force_mock: bool = False,
    require_real: bool = False,
) -> ChainState:
    rpc = rpc_url or os.getenv("GANACHE_RPC_URL", "http://127.0.0.1:7545")
    rpc_timeout = float(os.getenv("DUPMIX_RPC_TIMEOUT", "15"))
    if force_mock or Web3 is None:
        if require_real and not force_mock:
            raise RuntimeError("Real chain required but web3 is unavailable.")
        return ChainState(backend="mock", chain_id=chain_id)
    try:
        web3 = Web3(HTTPProvider(rpc, request_kwargs={"timeout": rpc_timeout}))
        if not web3.is_connected():
            raise RuntimeError("RPC unavailable")
        return ChainState(backend="web3", chain_id=chain_id, web3_provider=web3)
    except Exception as exc:
        if require_real:
            raise RuntimeError(f"Real chain required but RPC unavailable: {exc}") from exc
        logger.warning("Falling back to mock chain backend: %s", exc)
        return ChainState(backend="mock", chain_id=chain_id)


def _compile_contract(contract_path: str) -> Tuple[Any, Any]:
    from solcx import compile_files, get_installed_solc_versions, set_solc_version

    versions = get_installed_solc_versions()
    if not versions:
        raise RuntimeError("No local solc version available for py-solc-x.")
    set_solc_version(str(versions[-1]))
    compiled = compile_files(
        [contract_path],
        output_values=["abi", "bin"],
    )
    _, artifact = next(iter(compiled.items()))
    return artifact["abi"], artifact["bin"]


def _send_web3_tx(chain_state: ChainState, tx_callable: Any, sender: str) -> Dict[str, Any]:
    web3 = chain_state.web3_provider
    if web3 is None:
        raise RuntimeError("Missing web3 provider in chain state.")
    gas_limit = int(os.getenv("DUPMIX_TX_GAS_LIMIT", "30000000"))
    receipt_timeout = float(os.getenv("DUPMIX_RECEIPT_TIMEOUT", "180"))
    nonce = web3.eth.get_transaction_count(sender, "pending")
    tx_hash = tx_callable.transact({"from": sender, "nonce": nonce, "gas": gas_limit})
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=receipt_timeout)
    return {
        "tx_hash": tx_hash.hex(),
        "gas_used": int(receipt.gasUsed),
        "block_number": int(receipt.blockNumber),
        "status": int(receipt.status),
    }


def deploy_contract(chain_state: ChainState, contract_path: str = "contracts/AuditSystem.sol") -> ChainState:
    if chain_state.backend == "web3":
        try:
            abi, bytecode = _compile_contract(contract_path)
            chain_state.contract_abi = abi
            web3 = chain_state.web3_provider
            if web3 is None:
                raise RuntimeError("Missing web3 provider before contract deployment.")
            deployer = web3.eth.accounts[0]
            contract_cls = web3.eth.contract(abi=abi, bytecode=bytecode)
            tx_hash = contract_cls.constructor().transact({"from": deployer})
            receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
            chain_state.contract_address = receipt.contractAddress
            chain_state.contract = web3.eth.contract(address=receipt.contractAddress, abi=abi)
            return chain_state
        except Exception as exc:
            if os.getenv("DUPMIX_CHAIN_MODE", "mock").strip().lower() == "real":
                raise RuntimeError(f"Contract deployment failed in real-chain mode: {exc}") from exc
            logger.warning("Contract compilation failed, using mock backend: %s", exc)
    chain_state.backend = "mock"
    chain_state.contract_address = "mock://AuditSystem"
    chain_state.contract = {"name": "AuditSystemMock"}
    return chain_state


def record_upload(
    chain_state: ChainState,
    file_id: str,
    owner: str,
    t_hex: str,
    root: str,
    fee: int = 10,
    deposit: int = 25,
) -> Dict[str, Any]:
    if chain_state.backend == "web3":
        tx = _send_web3_tx(
            chain_state,
            chain_state.contract.functions.recordUpload(file_id, owner, t_hex, root, fee, deposit),
            owner,
        )
        record = {
            "owner": owner,
            "t": t_hex,
            "root": root,
            "fee": fee,
            "deposit": deposit,
            "block_number": tx["block_number"],
            "tx_hash": tx["tx_hash"],
            "gas_used": tx["gas_used"],
            "status": tx["status"],
        }
        chain_state.uploads[file_id] = record
        return record
    chain_state.current_block += 1
    chain_state.uploads[file_id] = {
        "owner": owner,
        "t": t_hex,
        "root": root,
        "fee": fee,
        "deposit": deposit,
        "block_number": chain_state.current_block,
    }
    chain_state.balances[owner] = chain_state.balances.get(owner, 0) - fee - deposit
    return chain_state.uploads[file_id]


def create_audit_request(
    chain_state: ChainState,
    challenge_id: str,
    file_id: str,
    requester: str,
    z_value: int,
) -> Dict[str, Any]:
    if chain_state.backend == "web3":
        tx = _send_web3_tx(
            chain_state,
            chain_state.contract.functions.createAuditRequest(challenge_id, file_id, requester, z_value),
            requester,
        )
        challenge = {
            "file_id": file_id,
            "requester": requester,
            "z": z_value,
            "block_number": tx["block_number"],
            "tx_hash": tx["tx_hash"],
            "gas_used": tx["gas_used"],
            "status": tx["status"],
        }
        chain_state.challenges[challenge_id] = challenge
        return challenge
    chain_state.current_block += 1
    chain_state.challenges[challenge_id] = {
        "file_id": file_id,
        "requester": requester,
        "z": z_value,
        "block_number": chain_state.current_block,
    }
    return chain_state.challenges[challenge_id]


def submit_proof_result(
    chain_state: ChainState,
    challenge_id: str,
    file_id: str,
    owner: str,
    csp_address: str,
    is_valid: bool,
    fee2: int = 7,
    fee1: int = 12,
    proof_payload_hex: str = "",
    proof_checksum: int = 0,
) -> Dict[str, Any]:
    if chain_state.backend == "web3":
        proof_payload = bytes.fromhex(proof_payload_hex) if proof_payload_hex else b""
        tx_prove = _send_web3_tx(
            chain_state,
            chain_state.contract.functions.benchmarkSubmitProof(challenge_id, proof_payload, int(proof_checksum)),
            csp_address,
        )
        tx_verify = _send_web3_tx(
            chain_state,
            chain_state.contract.functions.benchmarkVerifyProofAndSettle(
                challenge_id,
                owner,
                csp_address,
                int(proof_checksum),
                fee2,
                fee1,
                proof_payload,
            ),
            owner,
        )
        audit = chain_state.contract.functions.audits(challenge_id).call()
        result = {
            "challenge_id": challenge_id,
            "file_id": file_id,
            "is_valid": bool(audit[4]),
            "block_number": tx_verify["block_number"],
            "prove_tx_hash": tx_prove["tx_hash"],
            "verify_tx_hash": tx_verify["tx_hash"],
            "prove_gas_used": tx_prove["gas_used"],
            "verify_gas_used": tx_verify["gas_used"],
            "status": tx_verify["status"],
        }
        chain_state.proof_results[challenge_id] = result
        return result
    chain_state.current_block += 1
    if is_valid:
        chain_state.balances[csp_address] = chain_state.balances.get(csp_address, 0) + fee2
    else:
        chain_state.balances[owner] = chain_state.balances.get(owner, 0) + fee1
    result = {
        "challenge_id": challenge_id,
        "file_id": file_id,
        "is_valid": is_valid,
        "block_number": chain_state.current_block,
    }
    chain_state.proof_results[challenge_id] = result
    return result


def record_update(chain_state: ChainState, file_id: str, root: str, op_type: str) -> Dict[str, Any]:
    if chain_state.backend == "web3":
        if chain_state.web3_provider is None:
            raise RuntimeError("Missing web3 provider for recordUpdate.")
        sender = chain_state.uploads.get(file_id, {}).get("owner", chain_state.web3_provider.eth.accounts[0])
        tx = _send_web3_tx(
            chain_state,
            chain_state.contract.functions.recordUpdate(file_id, root, op_type),
            sender,
        )
        chain_state.uploads.setdefault(file_id, {})["root"] = root
        payload = {
            "file_id": file_id,
            "root": root,
            "op_type": op_type,
            "block_number": tx["block_number"],
            "tx_hash": tx["tx_hash"],
            "gas_used": tx["gas_used"],
            "status": tx["status"],
        }
        return payload
    chain_state.current_block += 1
    chain_state.uploads.setdefault(file_id, {})["root"] = root
    payload = {"file_id": file_id, "root": root, "op_type": op_type, "block_number": chain_state.current_block}
    return payload


def request_transfer(
    chain_state: ChainState,
    file_id: str,
    from_owner: str,
    to_owner: str,
    fee3: int = 9,
) -> Dict[str, Any]:
    if chain_state.backend == "web3":
        tx = _send_web3_tx(
            chain_state,
            chain_state.contract.functions.requestTransfer(file_id, from_owner, to_owner, fee3),
            to_owner,
        )
        transfer = {
            "file_id": file_id,
            "from_owner": from_owner,
            "to_owner": to_owner,
            "fee3": fee3,
            "status": "requested",
            "block_number": tx["block_number"],
            "tx_hash": tx["tx_hash"],
            "gas_used": tx["gas_used"],
            "status_code": tx["status"],
        }
        chain_state.transfers[file_id] = transfer
        return transfer
    chain_state.current_block += 1
    chain_state.balances[to_owner] = chain_state.balances.get(to_owner, 0) - fee3
    chain_state.balances[from_owner] = chain_state.balances.get(from_owner, 0) - (2 * fee3)
    transfer = {
        "file_id": file_id,
        "from_owner": from_owner,
        "to_owner": to_owner,
        "fee3": fee3,
        "status": "requested",
        "block_number": chain_state.current_block,
    }
    chain_state.transfers[file_id] = transfer
    return transfer


def settle_transfer(chain_state: ChainState, file_id: str, success: bool) -> Dict[str, Any]:
    if chain_state.backend == "web3":
        transfer = chain_state.transfers[file_id]
        sender = transfer["to_owner"]
        tx = _send_web3_tx(
            chain_state,
            chain_state.contract.functions.settleTransfer(file_id, success),
            sender,
        )
        transfer["status"] = "settled-success" if success else "settled-failed"
        transfer["block_number"] = tx["block_number"]
        transfer["tx_hash"] = tx["tx_hash"]
        transfer["gas_used"] = tx["gas_used"]
        transfer["status_code"] = tx["status"]
        return transfer
    chain_state.current_block += 1
    transfer = chain_state.transfers[file_id]
    fee3 = transfer["fee3"]
    if success:
        chain_state.balances[transfer["from_owner"]] = chain_state.balances.get(transfer["from_owner"], 0) + (2 * fee3)
        transfer["status"] = "settled-success"
    else:
        chain_state.balances[transfer["to_owner"]] = chain_state.balances.get(transfer["to_owner"], 0) + fee3
        transfer["status"] = "settled-failed"
    transfer["block_number"] = chain_state.current_block
    return transfer
