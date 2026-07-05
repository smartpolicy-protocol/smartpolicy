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

    /// @notice Gate on an off-chain authorization: a short-lived EIP-712 grant
    ///         signed by an issuer the policy authorized. Consumes the grant's
    ///         nonce — each grant admits exactly one call.
    /// @dev The policyId/action binding here is what stops a grant issued for
    ///      one purpose (e.g. "deposit") from being redeemed against another
    ///      (e.g. "sweep"). The verifier alone cannot know which action a
    ///      function represents, so the gate must pin it.
    modifier withGrant(
        uint256 policyId,
        bytes32 action,
        IGrantVerifier.Grant calldata grant,
        bytes calldata signature
    ) {
        if (address(policyGrantVerifier) == address(0)) revert GrantVerifierNotConfigured();
        if (grant.policyId != policyId) revert GrantPolicyMismatch(policyId, grant.policyId);
        if (grant.action != action) revert GrantActionMismatch(action, grant.action);
        if (grant.subject != msg.sender) revert GrantNotForCaller(grant.subject, msg.sender);
        policyGrantVerifier.consumeGrant(grant, signature);
        _;
    }
}
