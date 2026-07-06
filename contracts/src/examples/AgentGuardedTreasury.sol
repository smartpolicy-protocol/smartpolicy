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
    error PolicyInactiveAtDeploy(uint256 policyId);
    error UnexpectedPolicyOwner(uint256 policyId, address expected);

    /// @param expectedPolicyOwner the address you expect to own `policyId_`.
    ///        Validating this at deploy prevents binding the treasury to a
    ///        nonexistent policy id (which a stranger could later claim by
    ///        creating it) or to a policy governed by the wrong party.
    constructor(address registry_, address grantVerifier_, uint256 policyId_, address expectedPolicyOwner)
        PolicyGate(registry_, grantVerifier_)
    {
        if (!policyRegistry.isPolicyActive(policyId_)) revert PolicyInactiveAtDeploy(policyId_);
        if (!policyRegistry.isOwner(policyId_, expectedPolicyOwner)) {
            revert UnexpectedPolicyOwner(policyId_, expectedPolicyOwner);
        }
        policyId = policyId_;
    }

    /// @notice Anyone the policy allows may deposit. Typically the policy sets
    ///         ACTION_DEPOSIT to ANYONE so funding is open.
    function deposit() external payable onlyAllowed(policyId, ACTION_DEPOSIT) {
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice Members (the authorized agents) may withdraw. Removing an agent
    ///         from the policy revokes this instantly.
    /// @dev This example lets an authorized caller withdraw any amount, so it needs
    ///      no reentrancy guard (there is no per-caller accounting to corrupt). If
    ///      you adapt this with spend limits or internal balances, add a
    ///      reentrancy guard and follow checks-effects-interactions — do NOT copy
    ///      this shape verbatim into a contract that tracks state across the call.
    function withdraw(address payable to, uint256 amount) external onlyAllowed(policyId, ACTION_WITHDRAW) {
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit Withdrawn(msg.sender, to, amount);
    }

    /// @notice High-risk action, gated with the RECOMMENDED pattern: the caller
    ///         must be allowed on-chain (ACTION_SWEEP) AND present a fresh,
    ///         single-use EIP-712 grant whose signed `context` pins the exact
    ///         destination. So an issuer approves "sweep to THIS address"; a
    ///         compromised agent cannot redirect the funds, and revoking either
    ///         the membership/rule or the issuer stops it.
    function sweep(address payable to, IGrantVerifier.Grant calldata grant, bytes calldata signature)
        external
        onlyAllowedWithGrant(policyId, ACTION_SWEEP, keccak256(abi.encode(to)), grant, signature)
    {
        uint256 amount = address(this).balance;
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit Swept(msg.sender, to, amount);
    }
}
