// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IPolicyRegistry} from "./interfaces/IPolicyRegistry.sol";
import {IGrantVerifier} from "./interfaces/IGrantVerifier.sol";

/// @title PolicyGate
/// @notice The integration surface for protected contracts: inherit, point at
///         the registry, and gate functions with one modifier. The primary
///         modifier mirrors the protocol's canonical question — onlyAllowed
///         (may msg.sender perform this action under this policy?) — with
///         narrower membership/admin/grant modifiers for specific patterns.
abstract contract PolicyGate {
    IPolicyRegistry public immutable policyRegistry;
    /// @dev address(0) is valid when the integrator does not use grants.
    IGrantVerifier public immutable policyGrantVerifier;

    error NotAllowedByPolicy(uint256 policyId, address subject, bytes32 action);
    error NotPolicyMember(uint256 policyId, address subject);
    error NotPolicyAdmin(uint256 policyId, address subject);
    error PolicyNotActive(uint256 policyId);
    error GrantVerifierNotConfigured();
    error GrantNotForCaller(address subject, address caller);
    error GrantPolicyMismatch(uint256 expected, uint256 actual);
    error GrantActionMismatch(bytes32 expected, bytes32 actual);
    error GrantContextMismatch(bytes32 expected, bytes32 actual);

    error RegistryMismatch(address gateRegistry, address verifierRegistry);

    constructor(address registry_, address grantVerifier_) {
        require(registry_ != address(0), "registry is zero");
        // If grants are used, the verifier MUST check issuer authorization
        // against the same registry the gate checks membership against —
        // otherwise the two enforcement paths govern different policy
        // universes, an unrecoverable misconfig (both contracts are immutable).
        if (grantVerifier_ != address(0)) {
            address verifierRegistry = IGrantVerifier(grantVerifier_).registry();
            if (verifierRegistry != registry_) revert RegistryMismatch(registry_, verifierRegistry);
        }
        policyRegistry = IPolicyRegistry(registry_);
        policyGrantVerifier = IGrantVerifier(grantVerifier_);
    }

    /// @notice Gate on the canonical question: may msg.sender perform
    ///         `action` under `policyId`? Honors per-action rules (ANYONE,
    ///         NOBODY) and falls back to membership.
    modifier onlyAllowed(uint256 policyId, bytes32 action) {
        if (!policyRegistry.isAllowed(policyId, msg.sender, action)) {
            revert NotAllowedByPolicy(policyId, msg.sender, action);
        }
        _;
    }

    modifier onlyPolicyMember(uint256 policyId) {
        if (!policyRegistry.isPolicyActive(policyId)) revert PolicyNotActive(policyId);
        if (!policyRegistry.isMember(policyId, msg.sender)) revert NotPolicyMember(policyId, msg.sender);
        _;
    }

    modifier onlyPolicyAdmin(uint256 policyId) {
        if (!policyRegistry.isPolicyActive(policyId)) revert PolicyNotActive(policyId);
        if (!policyRegistry.isAdmin(policyId, msg.sender) && !policyRegistry.isOwner(policyId, msg.sender)) {
            revert NotPolicyAdmin(policyId, msg.sender);
        }
        _;
    }

    modifier whenPolicyActive(uint256 policyId) {
        if (!policyRegistry.isPolicyActive(policyId)) revert PolicyNotActive(policyId);
        _;
    }

    /// @notice Gate on an off-chain authorization ALONE: a short-lived EIP-712
    ///         grant signed by an issuer the policy authorized. The grant is
    ///         SUFFICIENT — the caller need not be an on-chain member. Use this
    ///         to authorize non-members off-chain (e.g. a one-time approval for
    ///         an external address).
    /// @dev REVOCATION: because this path does NOT consult `isAllowed`, removing
    ///      a member or setting an action to NOBODY does NOT stop outstanding
    ///      grants. The kill switch for the grant path is `removeIssuer` (plus
    ///      grant expiry). If you want on-chain rule/membership revocation to
    ///      also stop grants, use {onlyAllowedWithGrant} instead.
    /// @param context binds the call's sensitive parameters. Pass bytes32(0) for
    ///      no binding, or keccak256(abi.encode(...)) of the exact parameters the
    ///      issuer approved; the grant's signed `context` must match or the call
    ///      reverts. This is what lets an issuer approve "sweep to X", not "sweep".
    modifier withGrant(
        uint256 policyId,
        bytes32 action,
        bytes32 context,
        IGrantVerifier.Grant calldata grant,
        bytes calldata signature
    ) {
        _verifyAndConsumeGrant(policyId, action, context, grant, signature);
        _;
    }

    /// @notice The RECOMMENDED grant gate for fund-moving actions: requires BOTH
    ///         on-chain permission (`isAllowed`) AND a fresh single-use grant.
    ///         Two independent factors — registry membership/rules and off-chain
    ///         issuer approval — must agree. Revoking EITHER (removeMember /
    ///         setActionRule NOBODY, OR removeIssuer) stops the action.
    /// @param context see {withGrant}. For money movement, bind the recipient
    ///      (and ideally amount): keccak256(abi.encode(to, amount)).
    modifier onlyAllowedWithGrant(
        uint256 policyId,
        bytes32 action,
        bytes32 context,
        IGrantVerifier.Grant calldata grant,
        bytes calldata signature
    ) {
        if (!policyRegistry.isAllowed(policyId, msg.sender, action)) {
            revert NotAllowedByPolicy(policyId, msg.sender, action);
        }
        _verifyAndConsumeGrant(policyId, action, context, grant, signature);
        _;
    }

    /// @dev Binds the grant to (policyId, action, subject=caller, context) and
    ///      consumes it. The verifier separately enforces target=this contract,
    ///      the signature, issuer authorization, the validity window, and single
    ///      use. The gate must pin policyId/action here because the verifier
    ///      cannot know which action a given function represents.
    function _verifyAndConsumeGrant(
        uint256 policyId,
        bytes32 action,
        bytes32 context,
        IGrantVerifier.Grant calldata grant,
        bytes calldata signature
    ) private {
        if (address(policyGrantVerifier) == address(0)) revert GrantVerifierNotConfigured();
        if (grant.policyId != policyId) revert GrantPolicyMismatch(policyId, grant.policyId);
        if (grant.action != action) revert GrantActionMismatch(action, grant.action);
        if (grant.subject != msg.sender) revert GrantNotForCaller(grant.subject, msg.sender);
        if (grant.context != context) revert GrantContextMismatch(context, grant.context);
        policyGrantVerifier.consumeGrant(grant, signature);
    }
}
