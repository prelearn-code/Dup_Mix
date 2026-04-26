from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.flows.flow_common import build_parser, build_runtime, parse_public_blocks, prepare_uploaded_file, print_json
from src.protocol import ownership_transfer_protocol, retrieve_protocol


def main() -> None:
    parser = build_parser("Flow 4: ownership transfer, key re-wrap, CSP ownership update, buyer retrieval check, chain settlement.")
    args = parser.parse_args()
    rt = build_runtime(args.sectors_per_block, args.real_chain)
    file_bytes, upload = prepare_uploaded_file(rt, parse_public_blocks(args.public_blocks))

    transfer = ownership_transfer_protocol(rt.owner, rt.buyer, upload["file_id"], rt.csp, rt.chain, rt.engine)
    recovered = retrieve_protocol(rt.buyer, upload["file_id"], rt.csp, rt.engine, rt.buyer.UID, rt.buyer.W)

    print_json(
        {
            "flow": "ownership_transfer",
            "chain_backend": rt.chain.backend,
            "steps": [
                "prepare uploaded file state",
                "buyer requests transfer on chain",
                "old owner proves retrievability and current ownership",
                "CSP removes old owner from block owner sets",
                "CSP adds new owner and re-wraps private sector keys",
                "CSP updates local ownership metadata",
                "new owner generates UID/W and retrieves data",
                "chain settles transfer result",
            ],
            "file_id": upload["file_id"],
            "old_owner": transfer["old_owner"],
            "new_owner": transfer["new_owner"],
            "transfer_success": transfer["success"],
            "buyer_retrieve_match": recovered == file_bytes,
            "csp_current_owner": rt.csp.ownership.get(upload["file_id"]),
            "chain_transfer_record": rt.chain.transfers.get(upload["file_id"], {}),
        }
    )


if __name__ == "__main__":
    main()
