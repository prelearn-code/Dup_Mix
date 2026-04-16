from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Tuple

from solcx import compile_files, get_installed_solc_versions, set_solc_version
from web3 import HTTPProvider, Web3
from web3.exceptions import Web3RPCError


ROOT = Path(__file__).resolve().parents[2]


def connect_web3() -> Web3:
    rpc_url = os.getenv("GANACHE_RPC_URL", "http://127.0.0.1:7545")
    rpc_timeout = float(os.getenv("DUPMIX_RPC_TIMEOUT", "15"))
    w3 = Web3(HTTPProvider(rpc_url, request_kwargs={"timeout": rpc_timeout}))
    try:
        connected = w3.is_connected()
    except Exception as exc:
        raise RuntimeError(f"RPC connectivity check failed for {rpc_url}: {exc}") from exc
    if not connected:
        raise RuntimeError(f"Unable to connect to RPC: {rpc_url}")
    return w3


def compile_audit_system() -> Tuple[Any, str]:
    versions = get_installed_solc_versions()
    if not versions:
        raise RuntimeError("No local solc found in ~/.solcx. Install solc first for real-chain benchmarks.")
    version = str(versions[-1])
    set_solc_version(version)
    contract_path = str(ROOT / "contracts" / "AuditSystem.sol")
    compiled = compile_files(
        [contract_path],
        output_values=["abi", "bin"],
    )
    artifact = compiled[next(iter(compiled.keys()))]
    return artifact["abi"], artifact["bin"]


def deploy_audit_system(w3: Web3) -> Any:
    abi, bytecode = compile_audit_system()
    deployer = w3.eth.accounts[0]
    contract_cls = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = contract_cls.constructor().transact({"from": deployer})
    receipt_timeout = float(os.getenv("DUPMIX_RECEIPT_TIMEOUT", "180"))
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=receipt_timeout)
    return w3.eth.contract(address=receipt.contractAddress, abi=abi)


def send_tx_and_gas(w3: Web3, tx_callable: Any, sender: str, max_retries: int = 4) -> Dict[str, Any]:
    last_error: Exception | None = None
    gas_limit = int(os.getenv("DUPMIX_TX_GAS_LIMIT", "30000000"))
    receipt_timeout = float(os.getenv("DUPMIX_RECEIPT_TIMEOUT", "180"))
    for _ in range(max_retries):
        nonce = w3.eth.get_transaction_count(sender, "pending")
        try:
            tx_hash = tx_callable.transact({"from": sender, "nonce": nonce, "gas": gas_limit})
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=receipt_timeout)
            return {
                "tx_hash": tx_hash.hex(),
                "gas_used": int(receipt.gasUsed),
                "block_number": int(receipt.blockNumber),
                "status": int(receipt.status),
            }
        except Web3RPCError as exc:
            last_error = exc
            message = str(exc).lower()
            if "correct nonce" in message or "nonce" in message:
                continue
            raise
    if last_error is not None:
        raise last_error
    raise RuntimeError("send_tx_and_gas failed unexpectedly without an exception")
