// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title IGrantVerifier
/// @notice EIP-712 verification of short-lived, single-use authorization grants.
///         A grant is signed off-chain by an issuer the policy owner authorized
///         in the registry (IPolicyRegistry.addIssuer). It proves
///         "issuer I says subject S may perform action A under policy P until T".
///         This is the bridge that lets off-chain decisions (KYC checks, agent
///         policy evaluation, rate limits) gate on-chain or backend actions.
/// @dev Replaces the v1 TokenVerifier. Differences: proper EIP-712 domain
///      (chain- and contract-bound), mandatory single-use nonces namespaced
///      per issuer (one issuer cannot burn another's nonces), expiry is
///      issuer-set rather than derived from caller-supplied timestamps.
interface IGrantVerifier {
    struct Grant {
        uint256 policyId;
        address subject; // who is being authorized
        bytes32 action; // app-defined action identifier, e.g. keccak256("withdraw")
        uint64 issuedAt;
        uint64 expiresAt; // keep short: minutes, not days
        uint256 nonce; // single-use per issuer
        address issuer; // must satisfy registry.isAuthorizedIssuer(policyId, issuer)
        address target; // the only contract allowed to consumeGrant this grant (the integrator/gate)
        // Optional binding of the gated call's sensitive parameters. bytes32(0)
        // means "action-level only" (any parameters). A non-zero value is a
        // commitment the issuer signs — e.g. keccak256(abi.encode(to, amount)) —
        // and the gate (PolicyGate.withGrantBound / onlyAllowedWithGrant) checks
        // the actual call matches. This is what lets an issuer approve "sweep to
        // THIS address for AT MOST X", not merely "sweep". Without it, a grant
        // authorizes the action but not where the funds go.
        bytes32 context;
    }

    event GrantConsumed(
        uint256 indexed policyId, address indexed subject, bytes32 indexed action, address issuer, uint256 nonce
    );

    error GrantExpired();
    error GrantNotYetValid();
    error GrantNonceUsed();
    error GrantIssuerNotAuthorized();
    error GrantSignatureInvalid();
    error GrantPolicyInactive();
    /// @notice consumeGrant caller is not the grant's bound target. Prevents a
    ///         third party from front-running a broadcast grant to burn its
    ///         nonce and grief the gated action (the target must consume it).
    error GrantTargetMismatch();

    /// @notice Pure verification: signature, validity window, policy active,
    ///         issuer authorization, and nonce freshness. Does NOT consume the
    ///         nonce — use for previews and off-chain checks.
    function isGrantValid(Grant calldata grant, bytes calldata signature) external view returns (bool);

    /// @notice Verify and consume: same checks as isGrantValid, then marks the
    ///         nonce used. Reverts (typed errors above) on any failure.
    ///         Enforcement points call this exactly once per grant.
    function consumeGrant(Grant calldata grant, bytes calldata signature) external;

    /// @notice EIP-712 digest (domain-bound) for off-chain signers and tooling.
    function hashGrant(Grant calldata grant) external view returns (bytes32);

    function isNonceUsed(address issuer, uint256 nonce) external view returns (bool);

    /// @notice The registry this verifier checks issuer authorization against.
    function registry() external view returns (address);
}
