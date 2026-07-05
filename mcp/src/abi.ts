import { parseAbi } from "viem";

/** Minimal ABI: exactly the registry surface the server consumes. */
export const registryAbi = parseAbi([
  // events (the event indexer and receipt decoding depend on these)
  "event PolicyCreated(uint256 indexed policyId, address indexed owner, uint8 flags, uint64 expiresAt)",
  "event PolicyLocked(uint256 indexed policyId)",
  "event PolicyOwnershipTransferred(uint256 indexed policyId, address indexed previousOwner, address indexed newOwner)",
  "event PolicyMetadataUpdated(uint256 indexed policyId, string metadataURI, bytes32 metadataHash)",
  "event PolicyExpiryUpdated(uint256 indexed policyId, uint64 expiresAt)",
  "event MemberAdded(uint256 indexed policyId, address indexed member)",
  "event MemberRemoved(uint256 indexed policyId, address indexed member)",
  "event AdminAdded(uint256 indexed policyId, address indexed admin)",
  "event AdminRemoved(uint256 indexed policyId, address indexed admin)",
  "event IssuerAdded(uint256 indexed policyId, address indexed issuer)",
  "event IssuerRemoved(uint256 indexed policyId, address indexed issuer)",
  "event ActionRuleSet(uint256 indexed policyId, bytes32 indexed action, uint8 rule)",
  "event ConditionSet(uint256 indexed policyId, bytes32 indexed key, bytes value)",
  "event ConditionCleared(uint256 indexed policyId, bytes32 indexed key)",
  // the canonical question
  "function isAllowed(uint256 policyId, address subject, bytes32 action) view returns (bool)",
  // reads backing policy_get and the reasons in policy_check
  "function isPolicyActive(uint256 policyId) view returns (bool)",
  "function isMember(uint256 policyId, address account) view returns (bool)",
  "function isAdmin(uint256 policyId, address account) view returns (bool)",
  "function isOwner(uint256 policyId, address account) view returns (bool)",
  "function isAuthorizedIssuer(uint256 policyId, address issuer) view returns (bool)",
  "function getPolicy(uint256 policyId) view returns ((address owner, uint64 expiresAt, uint8 flags, bool locked, bytes32 metadataHash, string metadataURI))",
  "function getActionRule(uint256 policyId, bytes32 action) view returns (uint8)",
  "function getCondition(uint256 policyId, bytes32 key) view returns (bytes)",
  "function memberCount(uint256 policyId) view returns (uint256)",
  "function policyCount() view returns (uint256)",
  "function creationFee() view returns (uint256)",
  "function updateFee() view returns (uint256)",
  // writes (encoded into calldata for the caller's wallet — never submitted by us)
  "function createPolicy(uint8 flags, uint64 expiresAt, string metadataURI, bytes32 metadataHash) payable returns (uint256)",
  "function addMembers(uint256 policyId, address[] members) payable",
  "function removeMembers(uint256 policyId, address[] members) payable",
  "function setActionRule(uint256 policyId, bytes32 action, uint8 rule) payable",
  "function addIssuer(uint256 policyId, address issuer) payable",
  "function removeIssuer(uint256 policyId, address issuer) payable",
  "function addAdmin(uint256 policyId, address admin) payable",
  "function removeAdmin(uint256 policyId, address admin) payable",
  "function setCondition(uint256 policyId, bytes32 key, bytes value) payable",
  "function clearCondition(uint256 policyId, bytes32 key) payable",
  "function setExpiry(uint256 policyId, uint64 expiresAt) payable",
  "function setMetadataURI(uint256 policyId, string metadataURI, bytes32 metadataHash) payable",
  "function lockPolicy(uint256 policyId)",
  "function transferPolicyOwnership(uint256 policyId, address newOwner)",
]);

export const verifierAbi = parseAbi([
  "struct Grant { uint256 policyId; address subject; bytes32 action; uint64 issuedAt; uint64 expiresAt; uint256 nonce; address issuer; address target; }",
  "function isGrantValid(Grant grant, bytes signature) view returns (bool)",
  "function consumeGrant(Grant grant, bytes signature)",
  "function hashGrant(Grant grant) view returns (bytes32)",
  "function isNonceUsed(address issuer, uint256 nonce) view returns (bool)",
  "function registry() view returns (address)",
]);

export const actionRuleNames = ["UNSET", "MEMBERS", "ANYONE", "NOBODY"] as const;
export type ActionRuleName = (typeof actionRuleNames)[number];
