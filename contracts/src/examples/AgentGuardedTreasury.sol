// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PolicyGate} from "../PolicyGate.sol";
import {IGrantVerifier} from "../interfaces/IGrantVerifier.sol";

/// @title AgentGuardedTreasury
/// @notice Example integration: a treasury operated by AI agents whose
///         permissions live in a SmartPolicy policy instead of this contract.
///         Rotating agents, disabling an action, or requiring off-chain
///         approval are registry updates — this contract never redeploys.
contract AgentGuardedTreasury is PolicyGate {
    bytes32 public constant ACTION_DEPOSIT = keccak256("deposit");
    bytes32 public constant ACTION_WITHDRAW = keccak256("withdraw");
    bytes32 public constant ACTION_SWEEP = keccak256("sweep");

    uint256 public immutable policyId;

    event Deposited(address indexed from, uint256 amount);
    event Withdrawn(address indexed agent, address indexed to, uint256 amount);
    event Swept(address indexed agent, address indexed to, uint256 amount);

    error TransferFailed();

    constructor(address registry_, address grantVerifier_, uint256 policyId_) PolicyGate(registry_, grantVerifier_) {
        policyId = policyId_;
    }

    /// @notice Anyone the policy allows may deposit. Typically the policy sets
    ///         ACTION_DEPOSIT to ANYONE so funding is open.
    function deposit() external payable onlyAllowed(policyId, ACTION_DEPOSIT) {
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice Members (the authorized agents) may withdraw. Removing an agent
    ///         from the policy revokes this instantly.
    function withdraw(address payable to, uint256 amount) external onlyAllowed(policyId, ACTION_WITHDRAW) {
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit Withdrawn(msg.sender, to, amount);
    }

    /// @notice High-risk action: requires a fresh off-chain approval (an
    ///         EIP-712 grant from an authorized issuer) on every call, on top
    ///         of whatever the issuer's own checks were.
    function sweep(address payable to, IGrantVerifier.Grant calldata grant, bytes calldata signature)
        external
        withGrant(policyId, ACTION_SWEEP, grant, signature)
    {
        uint256 amount = address(this).balance;
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit Swept(msg.sender, to, amount);
    }
}
