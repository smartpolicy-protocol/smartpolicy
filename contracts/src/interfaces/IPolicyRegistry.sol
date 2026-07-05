// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @dev Bitfield values for Policy.flags (file-level: interfaces cannot hold constants).
uint8 constant FLAG_OPEN_MEMBERSHIP = 1 << 0; // any address counts as member
uint8 constant FLAG_TRANSFERABLE = 1 << 1; // owner may transfer ownership

/// @title IPolicyRegistry
/// @notice The single source of truth for policies: who may do what, under
///         which conditions, and whether the policy is live.
///
///         The canonical question — the one AI agents, backends, and contracts
///         all ask — is general: "may subject S perform action A under policy
///         P?" — answered by {isAllowed}. Membership is the default rule
///         backing that answer; per-action rules refine it without changing
///         the question.
///
///         The registry stores and serves rules; it never interprets condition
///         semantics — enforcement points (PolicyGate, the MCP server, app
///         backends) read and decide.
/// @dev The implementing contract is immutable by design: no proxy, no upgrade
///      path. Protocol evolution means deploying a new registry. The protocol
///      owner's only powers are fee parameters (hard-capped at deploy) and the
///      fee collector address — never policy data.
interface IPolicyRegistry {
    // ---------------------------------------------------------------------
    // Types
    // ---------------------------------------------------------------------

    struct Policy {
        address owner;
        uint64 expiresAt; // 0 = never expires
        uint8 flags;
        bool locked; // irreversibly frozen rules (still enforceable)
        bytes32 metadataHash; // keccak256 commitment to the metadata document; 0 = none
        string metadataURI; // off-chain description; informational only, never enforced
    }

    /// @notice Per-action refinement of the membership rule.
    /// @dev UNSET   → fall back to membership (the default for every action)
    ///      MEMBERS → explicit members-only (same as UNSET, but pinned)
    ///      ANYONE  → any address may perform this action
    ///      NOBODY  → action disabled for everyone
    enum ActionRule {
        UNSET,
        MEMBERS,
        ANYONE,
        NOBODY
    }

    // ---------------------------------------------------------------------
    // Events (the MCP server indexes these; every write must emit)
    // ---------------------------------------------------------------------

    event PolicyCreated(uint256 indexed policyId, address indexed owner, uint8 flags, uint64 expiresAt);
    event PolicyLocked(uint256 indexed policyId);
    event PolicyOwnershipTransferred(uint256 indexed policyId, address indexed previousOwner, address indexed newOwner);
    event PolicyMetadataUpdated(uint256 indexed policyId, string metadataURI, bytes32 metadataHash);
    event PolicyExpiryUpdated(uint256 indexed policyId, uint64 expiresAt);
    event MemberAdded(uint256 indexed policyId, address indexed member);
    event MemberRemoved(uint256 indexed policyId, address indexed member);
    event AdminAdded(uint256 indexed policyId, address indexed admin);
    event AdminRemoved(uint256 indexed policyId, address indexed admin);
    event IssuerAdded(uint256 indexed policyId, address indexed issuer);
    event IssuerRemoved(uint256 indexed policyId, address indexed issuer);
    event ActionRuleSet(uint256 indexed policyId, bytes32 indexed action, ActionRule rule);
    event ConditionSet(uint256 indexed policyId, bytes32 indexed key, bytes value);
    event ConditionCleared(uint256 indexed policyId, bytes32 indexed key);

    // ---------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------

    error PolicyNotFound(uint256 policyId);
    error PolicyIsLocked(uint256 policyId);
    error NotPolicyOwner(uint256 policyId, address caller);
    error NotPolicyOwnerOrAdmin(uint256 policyId, address caller);
    error PolicyNotTransferable(uint256 policyId);
    error WrongFee(uint256 expected, uint256 provided);
    error ZeroAddress();

    // ---------------------------------------------------------------------
    // Writes — policy lifecycle (owner only)
    // ---------------------------------------------------------------------

    /// @notice Create a policy. Payable: msg.value must equal creationFee().
    /// @param metadataHash keccak256 of the metadata document the URI points
    ///        at (tamper-evidence: anyone can verify the fetched document
    ///        matches what the owner committed). bytes32(0) = no commitment.
    ///        For content-immutable metadata use an ipfs:// URI as well.
    /// @return policyId Sequential ID starting at 1.
    function createPolicy(uint8 flags, uint64 expiresAt, string calldata metadataURI, bytes32 metadataHash)
        external
        payable
        returns (uint256 policyId);

    /// @notice Irreversibly freeze the policy's rules. The policy remains
    ///         enforceable; no further writes of any kind are accepted.
    function lockPolicy(uint256 policyId) external;

    /// @notice Allowed only when FLAG_TRANSFERABLE is set and not locked.
    function transferPolicyOwnership(uint256 policyId, address newOwner) external;

    function addAdmin(uint256 policyId, address admin) external payable;
    function removeAdmin(uint256 policyId, address admin) external payable;

    // ---------------------------------------------------------------------
    // Writes — rules (owner or admin; payable: msg.value must equal updateFee())
    // ---------------------------------------------------------------------

    function addMembers(uint256 policyId, address[] calldata members) external payable;
    function removeMembers(uint256 policyId, address[] calldata members) external payable;

    /// @notice Refine who may perform a specific action (see ActionRule).
    function setActionRule(uint256 policyId, bytes32 action, ActionRule rule) external payable;

    /// @notice Authorize an address to sign EIP-712 grants for this policy
    ///         (consumed by the GrantVerifier; see IGrantVerifier).
    function addIssuer(uint256 policyId, address issuer) external payable;
    function removeIssuer(uint256 policyId, address issuer) external payable;

    /// @notice Set an arbitrary condition value. The registry stores bytes;
    ///         typed-value conventions live in the SDK.
    function setCondition(uint256 policyId, bytes32 key, bytes calldata value) external payable;
    function clearCondition(uint256 policyId, bytes32 key) external payable;

    function setExpiry(uint256 policyId, uint64 expiresAt) external payable;

    /// @notice Update metadata pointer + commitment together (atomic).
    function setMetadataURI(uint256 policyId, string calldata metadataURI, bytes32 metadataHash) external payable;

    // ---------------------------------------------------------------------
    // Reads (always free; this is the enforcement surface)
    // ---------------------------------------------------------------------

    /// @notice THE canonical question: may `subject` perform `action` under
    ///         this policy? False when the policy is inactive; otherwise
    ///         resolved by the action's rule (membership when UNSET/MEMBERS,
    ///         true when ANYONE, false when NOBODY).
    function isAllowed(uint256 policyId, address subject, bytes32 action) external view returns (bool);

    /// @notice True iff the policy exists and is not expired. Locked policies
    ///         remain active — locking freezes rules, not enforcement.
    function isPolicyActive(uint256 policyId) external view returns (bool);

    /// @notice True iff `account` is a member, or the policy has open membership.
    function isMember(uint256 policyId, address account) external view returns (bool);

    function isAdmin(uint256 policyId, address account) external view returns (bool);
    function isOwner(uint256 policyId, address account) external view returns (bool);

    /// @notice True iff `issuer` may sign grants for this policy.
    function isAuthorizedIssuer(uint256 policyId, address issuer) external view returns (bool);

    function getPolicy(uint256 policyId) external view returns (Policy memory);
    function getActionRule(uint256 policyId, bytes32 action) external view returns (ActionRule);
    function getCondition(uint256 policyId, bytes32 key) external view returns (bytes memory);
    function memberCount(uint256 policyId) external view returns (uint256);
    function policyCount() external view returns (uint256);

    // ---------------------------------------------------------------------
    // Fees
    // ---------------------------------------------------------------------

    function creationFee() external view returns (uint256);
    function updateFee() external view returns (uint256);
}
