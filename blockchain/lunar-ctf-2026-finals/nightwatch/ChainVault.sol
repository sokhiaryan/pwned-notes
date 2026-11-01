// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAuditorRegistry {
    function isAuditor(address _addr) external view returns (bool);
}

/// @title KumoSec ChainVault — Hardened Bug Bounty Escrow Vault
/// @notice Manages escrowed ETH for KumoSec's security audit bounty program.
/// @dev Integrates with AuditorRegistry for access control on settlements.
///      Implements emergency shutdown when vault balance is completely drained.
contract ChainVault {

    // ── Structs ──────────────────────────────────────────────────────

    struct Bounty {
        bytes32 bountyId;
        address client;
        uint256 amount;
        bool settled;
    }

    // ── State ────────────────────────────────────────────────────────

    address public owner;
    IAuditorRegistry public auditorRegistry;

    uint256 public emergencyThreshold;
    bool public emergencyMode;
    bool public isSolved;

    uint256 public totalDeposited;
    uint256 public totalClaimed;

    mapping(bytes32 => Bounty) public bounties;
    bytes32[] public bountyList;

    mapping(address => uint256) public pendingClaims;
    mapping(address => bytes32) public activeClaimBounty;

    // ── Events ───────────────────────────────────────────────────────

    event BountyDeposited(bytes32 indexed bountyId, address indexed client, uint256 amount);
    event FindingSubmitted(address indexed auditor, bytes32 indexed bountyId, string findingRef);
    event ClaimSettled(address indexed auditor, uint256 amount);
    event EmergencyShutdown(address indexed triggeredBy, uint256 remainingBalance, bytes32 proof);
    event VaultStatusChanged(string status);

    // ── Modifiers ────────────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "ChainVault: not owner");
        _;
    }

    modifier onlyAuditor() {
        require(
            auditorRegistry.isAuditor(msg.sender),
            "ChainVault: caller is not a registered auditor"
        );
        _;
    }

    modifier notInEmergency() {
        require(!emergencyMode, "ChainVault: vault is in emergency mode");
        _;
    }

    // ── Constructor ──────────────────────────────────────────────────

    constructor(
        address _registry,
        uint256 _threshold
    ) payable {
        require(_registry != address(0), "Zero registry address");
        owner = msg.sender;
        auditorRegistry = IAuditorRegistry(_registry);
        emergencyThreshold = _threshold;

        if (msg.value > 0) {
            totalDeposited += msg.value;
        }
        emit VaultStatusChanged("initialized");
    }

    // ── Client Functions ─────────────────────────────────────────────

    /// @notice Deposit ETH for a specific audit bounty
    function depositBounty(bytes32 _bountyId) external payable notInEmergency {
        require(msg.value > 0, "Must deposit ETH");
        require(bounties[_bountyId].amount == 0, "Bounty already exists");

        bounties[_bountyId] = Bounty({
            bountyId: _bountyId,
            client: msg.sender,
            amount: msg.value,
            settled: false
        });
        bountyList.push(_bountyId);
        totalDeposited += msg.value;

        emit BountyDeposited(_bountyId, msg.sender, msg.value);
    }

    // ── Auditor Functions ────────────────────────────────────────────

    /// @notice Submit an audit report finding for an active bounty
    function submitAuditFinding(
        bytes32 _bountyId,
        string calldata _findingRef
    ) external onlyAuditor notInEmergency {
        Bounty storage b = bounties[_bountyId];
        require(b.amount > 0, "Bounty does not exist");
        require(!b.settled, "Bounty already settled");
        require(pendingClaims[msg.sender] == 0, "Auditor already has an active pending claim");

        // Credit 1 ether allowance for validated finding
        uint256 claimAmount = b.amount > 1 ether ? 1 ether : b.amount;
        pendingClaims[msg.sender] = claimAmount;
        activeClaimBounty[msg.sender] = _bountyId;

        emit FindingSubmitted(msg.sender, _bountyId, _findingRef);
    }

    /// @notice Settle and withdraw approved bounty finding reward
    function settleClaim() external onlyAuditor notInEmergency {
        uint256 amount = pendingClaims[msg.sender];
        require(amount > 0, "No pending claim to settle");
        require(address(this).balance >= amount, "Insufficient vault balance");

        // External call to transfer payout reward
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Payout transfer failed");

        // State update performed after external call (CEI violation)
        pendingClaims[msg.sender] = 0;
        totalClaimed += amount;

        bytes32 bId = activeClaimBounty[msg.sender];
        if (bId != bytes32(0)) {
            bounties[bId].settled = true;
            activeClaimBounty[msg.sender] = bytes32(0);
        }

        emit ClaimSettled(msg.sender, amount);
        _checkEmergencyCondition();
    }

    // ── Internal ─────────────────────────────────────────────────────

    function _checkEmergencyCondition() internal {
        if (address(this).balance <= emergencyThreshold && !emergencyMode) {
            emergencyMode = true;
            isSolved = true;
            bytes32 proof = keccak256(
                abi.encodePacked("CHAINVAULT_PWNED", address(this), msg.sender, block.number)
            );
            emit EmergencyShutdown(
                msg.sender,
                address(this).balance,
                proof
            );
            emit VaultStatusChanged("emergency_shutdown");
        }
    }

    // ── View Functions ───────────────────────────────────────────────

    function getBountyCount() external view returns (uint256) {
        return bountyList.length;
    }

    function getBountyIdAt(uint256 index) external view returns (bytes32) {
        require(index < bountyList.length, "Index out of bounds");
        return bountyList[index];
    }

    function getVaultStatus()
        external
        view
        returns (
            uint256 balance,
            uint256 threshold,
            bool isEmergency,
            bool solved,
            uint256 deposited,
            uint256 claimed,
            address registry
        )
    {
        return (
            address(this).balance,
            emergencyThreshold,
            emergencyMode,
            isSolved,
            totalDeposited,
            totalClaimed,
            address(auditorRegistry)
        );
    }

    function isHealthy() external view returns (bool) {
        return address(this).balance > emergencyThreshold && !emergencyMode;
    }

    receive() external payable {
        totalDeposited += msg.value;
    }
}
