from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.flows.flow_common import build_parser, build_runtime, parse_public_blocks, prepare_uploaded_file, print_json
from src.protocol import retrieve_protocol


def main() -> None:
    parser = build_parser("Flow 3: user retrieval, CSP identity verification, key payload unwrap, private sector decrypt.")
    args = parser.parse_args()
    rt = build_runtime(args.sectors_per_block, args.real_chain)
    file_bytes, upload = prepare_uploaded_file(rt, parse_public_blocks(args.public_blocks))
    file_state = rt.csp.files[upload["file_id"]]

    recovered = retrieve_protocol(rt.owner, upload["file_id"], rt.csp, rt.engine, upload["UID"], upload["W"])

    print_json(
        {
            "flow": "retrieve_decrypt",
            "chain_backend": rt.chain.backend,
            "steps": [
                "prepare uploaded file state",
                "user sends file id and UID/W",
                "CSP verifies current ownership",
                "CSP verifies user identity pairing equation",
                "user unwraps private block key payloads",
                "user decrypts private sectors with H3(k) xor ciphertext",
                "user joins blocks and removes padding by original file size",
            ],
            "file_id": upload["file_id"],
            "file_size": file_state.file_size,
            "block_count": len(file_state.block_ids),
            "private_block_count": len(file_state.block_ids) - len(file_state.public_blocks),
            "recovered_size": len(recovered),
            "retrieve_match": recovered == file_bytes,
        }
    )


if __name__ == "__main__":
    main()
