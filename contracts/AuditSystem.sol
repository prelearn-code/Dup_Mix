// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library Pairing {
    uint256 constant FIELD_MODULUS = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    function P2() internal pure returns (G2Point memory) {
        return G2Point(
            [
                uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634),
                uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781)
            ],
            [
                uint256(4082367875863433681332203403145435568316851327593401208105741076214120093531),
                uint256(8495653923123431417604973247489272438418190587263600148770280649306958101930)
            ]
        );
    }

    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        if (p.X == 0 && p.Y == 0) {
            return G1Point(0, 0);
        }
        return G1Point(p.X, FIELD_MODULUS - (p.Y % FIELD_MODULUS));
    }

    function pairing(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2
    ) internal view returns (bool) {
        uint256[] memory input = new uint256[](12);
        input[0] = a1.X;
        input[1] = a1.Y;
        input[2] = a2.X[0];
        input[3] = a2.X[1];
        input[4] = a2.Y[0];
        input[5] = a2.Y[1];
        input[6] = b1.X;
        input[7] = b1.Y;
        input[8] = b2.X[0];
        input[9] = b2.X[1];
        input[10] = b2.Y[0];
        input[11] = b2.Y[1];
        uint256[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), 0x180, out, 0x20)
        }
        require(success, "pairing precompile failed");
        return out[0] != 0;
    }
}

contract AuditSystem {
    struct UploadRecord {
        address owner;
        string tValue;
        string root;
        uint256 fee;
        uint256 deposit;
        bool exists;
    }

    struct AuditRecord {
        string fileId;
        address requester;
        uint256 zValue;
        bool settled;
        bool result;
    }

    struct TransferRecord {
        address fromOwner;
        address toOwner;
        uint256 fee3;
        bool settled;
        bool success;
    }

    mapping(string => UploadRecord) public uploads;
    mapping(string => AuditRecord) public audits;
    mapping(string => TransferRecord) public transfers;
    mapping(address => int256) public balances;
    mapping(string => bytes32) public auditProofHash;
    mapping(string => uint256) public auditProofChecksum;
    mapping(string => bytes32) public auditProofDigest;
    mapping(string => bool) public transferOwnerVerified;
    mapping(string => bool) public transferCspUpdated;
    mapping(string => bytes32) public transferOwnerAttestation;
    mapping(string => bytes32) public transferCspStateRoot;

    uint256 private constant CHECKSUM_MOD = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    event StorageUploaded(string indexed fileId, address indexed owner, string tValue, string root);
    event AuditRequested(string indexed challengeId, string indexed fileId, address indexed requester);
    event ChallengeGenerated(string indexed challengeId, uint256 zValue);
    event AuditVerified(string indexed challengeId, bool isValid);
    event AuditPairingVerified(string indexed challengeId, bool isValid);
    event UpdateCommitted(string indexed fileId, string root, string opType);
    event OwnershipTransferRequested(string indexed fileId, address indexed fromOwner, address indexed toOwner);
    event OwnershipTransferSettled(string indexed fileId, bool success);

    function recordUpload(
        string calldata fileId,
        address owner,
        string calldata tValue,
        string calldata root,
        uint256 fee,
        uint256 deposit
    ) external {
        uploads[fileId] = UploadRecord(owner, tValue, root, fee, deposit, true);
        balances[owner] -= int256(fee + deposit);
        emit StorageUploaded(fileId, owner, tValue, root);
    }

    function createAuditRequest(
        string calldata challengeId,
        string calldata fileId,
        address requester,
        uint256 zValue
    ) external {
        audits[challengeId] = AuditRecord(fileId, requester, zValue, false, false);
        emit AuditRequested(challengeId, fileId, requester);
        emit ChallengeGenerated(challengeId, zValue);
    }

    /// @notice Settle an audit after off-chain PBC verification.
    /// @dev The paper VerifyProof equation is not evaluated in this function.
    ///      The caller supplies the boolean result produced by the Python/C-PBC path:
    ///      e(sigma_c, g) == prod_i e(base_i, Y_i)^{v_i}.
    function submitProofResult(
        string calldata challengeId,
        address owner,
        address csp,
        bool isValid,
        uint256 fee2,
        uint256 fee1
    ) external {
        AuditRecord storage audit = audits[challengeId];
        audit.settled = true;
        audit.result = isValid;
        if (isValid) {
            balances[csp] += int256(fee2);
        } else {
            balances[owner] += int256(fee1);
        }
        emit AuditVerified(challengeId, isValid);
    }

    // Benchmark stage: CSP submits proof commitment on-chain.
    function benchmarkSubmitProof(
        string calldata challengeId,
        bytes calldata proofBlob,
        uint256 proofChecksum
    ) external {
        require(audits[challengeId].requester != address(0), "challenge not found");
        auditProofChecksum[challengeId] = proofChecksum;
        bytes32 digest = keccak256(proofBlob);
        auditProofDigest[challengeId] = digest;
        uint256 rolling = uint256(digest);
        uint256 zValue = audits[challengeId].zValue;
        for (uint256 i = 0; i < zValue; i++) {
            rolling = uint256(keccak256(abi.encodePacked(rolling, i, challengeId)));
        }
        auditProofHash[challengeId] = bytes32(rolling);
    }

    /// @notice Benchmark-only commitment verification + settlement.
    /// @dev This checks proof blob integrity with keccak/checksum work so the H gas
    ///      experiment has a chain-side verification stage. It is not the paper
    ///      pairing equation.
    function benchmarkVerifyProofAndSettle(
        string calldata challengeId,
        address owner,
        address csp,
        uint256 expectedChecksum,
        uint256 fee2,
        uint256 fee1,
        bytes calldata proof
    ) external {
        require(auditProofDigest[challengeId] != bytes32(0), "proof not submitted");
        require(keccak256(proof) == auditProofDigest[challengeId], "proof mismatch");
        bool isValid;
        {
            uint256 checksum = 0;
            for (uint256 i = 0; i < proof.length; i++) {
                checksum = (checksum + (uint8(proof[i]) * (i + 1))) % CHECKSUM_MOD;
            }
            uint256 rolling = uint256(auditProofDigest[challengeId]);
            uint256 zValue = audits[challengeId].zValue;
            for (uint256 i = 0; i < zValue; i++) {
                rolling = uint256(keccak256(abi.encodePacked(rolling, i, challengeId)));
            }
            isValid = (checksum == expectedChecksum) && 
                      (auditProofChecksum[challengeId] == expectedChecksum) && 
                      (bytes32(rolling) == auditProofHash[challengeId]);
        }
        
        audits[challengeId].settled = true;
        audits[challengeId].result = isValid;
        if (isValid) {
            balances[csp] += int256(fee2);
        } else {
            balances[owner] += int256(fee1);
        }
        emit AuditVerified(challengeId, isValid);
    }

    /// @notice Chain-side BN254 pairing verification used by the H gas experiment.
    /// @dev Verifies e(-sigmaC, P2) * e(baseAgg, yAgg) == 1 through precompile 0x08,
    ///      equivalent to e(sigmaC, P2) == e(baseAgg, yAgg). This mirrors the
    ///      audit formula shape but uses BN254 fixture points instead of the
    ///      Python/PBC Type-A proof state.
    function verifyBn254ProofAndSettle(
        string calldata challengeId,
        address owner,
        address csp,
        uint256[2] calldata sigmaC,
        uint256[2] calldata baseAgg,
        uint256[4] calldata yAgg,
        uint256 fee2,
        uint256 fee1
    ) external {
        require(audits[challengeId].requester != address(0), "challenge not found");
        Pairing.G1Point memory sigmaPoint = Pairing.G1Point(sigmaC[0], sigmaC[1]);
        Pairing.G1Point memory basePoint = Pairing.G1Point(baseAgg[0], baseAgg[1]);
        Pairing.G2Point memory yPoint = Pairing.G2Point([yAgg[0], yAgg[1]], [yAgg[2], yAgg[3]]);
        bool isValid = Pairing.pairing(Pairing.negate(sigmaPoint), Pairing.P2(), basePoint, yPoint);

        audits[challengeId].settled = true;
        audits[challengeId].result = isValid;
        if (isValid) {
            balances[csp] += int256(fee2);
        } else {
            balances[owner] += int256(fee1);
        }
        emit AuditVerified(challengeId, isValid);
        emit AuditPairingVerified(challengeId, isValid);
    }

    function recordUpdate(string calldata fileId, string calldata root, string calldata opType) external {
        uploads[fileId].root = root;
        emit UpdateCommitted(fileId, root, opType);
    }

    function requestTransfer(
        string calldata fileId,
        address fromOwner,
        address toOwner,
        uint256 fee3
    ) external {
        transfers[fileId] = TransferRecord(fromOwner, toOwner, fee3, false, false);
        balances[toOwner] -= int256(fee3);
        balances[fromOwner] -= int256(2 * fee3);
        transferOwnerVerified[fileId] = false;
        transferCspUpdated[fileId] = false;
        transferOwnerAttestation[fileId] = bytes32(0);
        transferCspStateRoot[fileId] = bytes32(0);
        emit OwnershipTransferRequested(fileId, fromOwner, toOwner);
    }

    // Benchmark stage: original owner identity confirmation.
    function benchmarkVerifyTransferOwner(
        string calldata fileId,
        address claimedFromOwner,
        bytes32 ownerAttestation
    ) external {
        require(transfers[fileId].fromOwner == claimedFromOwner, "owner mismatch");
        require(ownerAttestation != bytes32(0), "invalid attestation");
        transferOwnerAttestation[fileId] = ownerAttestation;
        transferOwnerVerified[fileId] = true;
    }

    // Benchmark stage: CSP updates ownership metadata.
    function benchmarkCspUpdateTransfer(string calldata fileId, bytes32 newOwnershipRoot) external {
        require(transferOwnerVerified[fileId], "owner not verified");
        require(newOwnershipRoot != bytes32(0), "invalid root");
        transferCspStateRoot[fileId] = newOwnershipRoot;
        transferCspUpdated[fileId] = true;
    }

    // Benchmark stage: transaction finalization.
    function benchmarkFinalizeTransfer(string calldata fileId, bool success) external {
        require(transferCspUpdated[fileId], "csp not updated");
        TransferRecord storage transfer = transfers[fileId];
        transfer.settled = true;
        transfer.success = success;
        if (success) {
            balances[transfer.fromOwner] += int256(2 * transfer.fee3);
        } else {
            balances[transfer.toOwner] += int256(transfer.fee3);
        }
        emit OwnershipTransferSettled(fileId, success);
    }

    function settleTransfer(string calldata fileId, bool success) external {
        TransferRecord storage transfer = transfers[fileId];
        transfer.settled = true;
        transfer.success = success;
        if (success) {
            balances[transfer.fromOwner] += int256(2 * transfer.fee3);
        } else {
            balances[transfer.toOwner] += int256(transfer.fee3);
        }
        emit OwnershipTransferSettled(fileId, success);
    }
}
