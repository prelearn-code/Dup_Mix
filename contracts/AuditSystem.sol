// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

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

    // Benchmark stage: chain-side verification + settlement.
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
