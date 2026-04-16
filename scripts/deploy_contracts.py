from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.chain import connect_chain, deploy_contract
from src.utils import ConfigLoader, load_environment


def main() -> None:
    load_environment()
    config = ConfigLoader()
    chain = connect_chain(chain_id=int(config.get("chain_id", 1337)))
    chain = deploy_contract(chain, str(ROOT / "contracts" / "AuditSystem.sol"))
    print(f"backend={chain.backend}")
    print(f"contract_address={chain.contract_address}")


if __name__ == "__main__":
    main()
