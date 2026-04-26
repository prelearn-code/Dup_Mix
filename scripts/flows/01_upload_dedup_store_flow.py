from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.flows.flow_common import build_parser, build_runtime, parse_public_blocks, prepare_uploaded_file, print_json


def main() -> None:
    parser = build_parser("Flow 1: user upload, dedup check, CSP identity verification, local tree update, chain upload record.")
    args = parser.parse_args()
    rt = build_runtime(args.sectors_per_block, args.real_chain)
    public_blocks = parse_public_blocks(args.public_blocks)
    file_bytes, upload = prepare_uploaded_file(rt, public_blocks)
    file_state = rt.csp.files[upload["file_id"]]

    print_json(
        {
            "flow": "upload_dedup_store",
            "chain_backend": rt.chain.backend,
            "steps": [
                "setup global parameters and users",
                "split file into blocks/sectors",
                "generate file key and sector keys",
                "encrypt private sectors with H3(k) xor data",
                "generate file tag and block tags",
                "generate UID/W and verify user identity at CSP",
                "run file/block dedup checks",
                "generate and verify block authenticators",
                "store CSP metadata/key payload/authenticators",
                "build local MHT/AVT root",
                "record upload metadata on chain",
            ],
            "file_id": upload["file_id"],
            "file_size": len(file_bytes),
            "duplicate_file": upload["duplicate_file"],
            "block_count": len(file_state.block_ids),
            "public_blocks": sorted(file_state.public_blocks),
            "mht_root": file_state.mht_root,
            "chain_upload_record": rt.chain.uploads.get(upload["file_id"], {}),
            "csp_file_index_size": len(rt.csp.file_index),
            "csp_block_index_size": len(rt.csp.block_index),
            "authenticator_count": len(rt.csp.authenticators),
        }
    )


if __name__ == "__main__":
    main()
