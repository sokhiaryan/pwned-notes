// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title KumoSec ChainVault — Auditor Registry
/// @notice Manages authorized security auditors for the KumoSec bounty ecosystem.
/// @dev Part of the ChainVault infrastructure. Auditors must be registered here
///      before they can interact with the BountyVault withdrawal functions.
contract AuditorRegistry {

    // ── State ────────────────────────────────────────────────────────

    address public owner;
    uint256 public totalRegistered;

    mapping(address => bool) public registeredAuditors;
    mapping(address => uint256) public registrationTimestamp;
    mapping(bytes32 => bool) public legacyMigrationTokens;

    // ── Events ───────────────────────────────────────────────────────

    event AuditorRegistered(address indexed auditor, string method);
    event AuditorRevoked(address indexed auditor);
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );

    // ── Modifiers ────────────────────────────────────────────────────

    modifier onlyOwner() {
        require(
            msg.sender == owner,
            "AuditorRegistry: caller is not the owner"
        );
        _;
    }

    // ── Constructor ──────────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // ── Owner Functions ──────────────────────────────────────────────

    /// @notice Transfer ownership of the registry
    function transferOwnership(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "New owner is zero address");
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }

    /// @notice Register a new auditor directly (owner only)
    function registerAuditor(address _auditor) external onlyOwner {
        require(_auditor != address(0), "Zero address");
        require(!registeredAuditors[_auditor], "Already registered");
        registeredAuditors[_auditor] = true;
        registrationTimestamp[_auditor] = block.timestamp;
        totalRegistered++;
        emit AuditorRegistered(_auditor, "owner_direct");
    }

    /// @notice Revoke an auditor's registration (owner only)
    function revokeAuditor(address _auditor) external onlyOwner {
        require(registeredAuditors[_auditor], "Not registered");
        registeredAuditors[_auditor] = false;
        totalRegistered--;
        emit AuditorRevoked(_auditor);
    }

    /// @notice Seed a one-time migration token for legacy v1 system import (owner only)
    function seedMigrationToken(bytes32 _token) external onlyOwner {
        legacyMigrationTokens[_token] = true;
    }

    // ── Public View Functions ────────────────────────────────────────

    /// @notice Check if an address is a registered auditor
    function isAuditor(address _addr) external view returns (bool) {
        return registeredAuditors[_addr];
    }

    /// @notice Get auditor registration details
    function getAuditorInfo(
        address _addr
    ) external view returns (bool registered, uint256 registeredAt) {
        return (registeredAuditors[_addr], registrationTimestamp[_addr]);
    }

    // ── Legacy Migration ─────────────────────────────────────────────

    /// @notice Migrate an auditor from the legacy v1 system using a migration token.
    /// @param _auditor The address to register as an auditor.
    /// @param _token   The one-time migration token from the legacy system.
    /// @dev Migration tokens are single-use and consumed upon successful migration.
    //  NOTE: This function is for backward compatibility with ChainVault v1
    //  auditors. It uses pre-seeded migration tokens to verify legitimacy.
    function migrateLegacyAuditor(
        address _auditor,
        bytes32 _token
    ) external {
        require(
            legacyMigrationTokens[_token],
            "Invalid or consumed migration token"
        );
        require(_auditor != address(0), "Zero address");
        require(!registeredAuditors[_auditor], "Already registered");

        legacyMigrationTokens[_token] = false;
        registeredAuditors[_auditor] = true;
        registrationTimestamp[_auditor] = block.timestamp;
        totalRegistered++;

        emit AuditorRegistered(_auditor, "legacy_v1_migration");
    }
}
