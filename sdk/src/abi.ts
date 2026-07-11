import { parseAbi } from "viem";

/** The registry surface the SDK reads from and encodes calldata against. */
export const registryAbi = parseAbi([
  "function isAllowed(uint256 policyId, address subject, bytes32 action) view returns (bool)",
  "function isPolicyActive(uint256 policyId) view returns (bool)",
  "function isMember(uint256 policyId, address account) view returns (bool)",
  "function isAdmin(uint256 policyId, address account) view returns (bool)",
  "function isOwner(uint256 policyId, address account) view returns (bool)",
  "function isAuthorizedIssuer(uint256 policyId, address issuer) view returns (bool)",
  "function getPolicy(uint256 policyId) view returns ((address owner, uint64 expiresAt, uint8 flags, bool locked, bytes32 metadataHash, string metadataURI))",
  "function getActionRule(uint256 policyId, bytes32 action) view returns (uint8)",
  "function memberCount(uint256 policyId) view returns (uint256)",
  "function policyCount() view returns (uint256)",
  "function pendingPolicyOwner(uint256 policyId) view returns (address)",
  "function creationFee() view returns (uint256)",
  "function updateFee() view returns (uint256)",
  // writes — encoded into unsigned calldata for the caller's own wallet
  "function createPolicy(uint8 flags, uint64 expiresAt, string metadataURI, bytes32 metadataHash) payable returns (uint256)",
  "function addMembers(uint256 policyId, address[] members) payable",
  "function removeMembers(uint256 policyId, address[] members) payable",
  "function setActionRule(uint256 policyId, bytes32 action, uint8 rule) payable",
  "function addIssuer(uint256 policyId, address issuer) payable",
  "function removeIssuer(uint256 policyId, address issuer) payable",
  "function addAdmin(uint256 policyId, address admin) payable",
  "function removeAdmin(uint256 policyId, address admin) payable",
  "function setExpiry(uint256 policyId, uint64 expiresAt) payable",
  "function lockPolicy(uint256 policyId)",
  "function transferPolicyOwnership(uint256 policyId, address newOwner)",
  "function acceptPolicyOwnership(uint256 policyId)",
]);

/** The grant verifier surface (v2 — 9-field Grant with `context`). */
export const verifierAbi = parseAbi([
  "struct Grant { uint256 policyId; address subject; bytes32 action; uint64 issuedAt; uint64 expiresAt; uint256 nonce; address issuer; address target; bytes32 context; }",
  "function isGrantValid(Grant grant, bytes signature) view returns (bool)",
  "function hashGrant(Grant grant) view returns (bytes32)",
  "function isNonceUsed(address issuer, uint256 nonce) view returns (bool)",
  "function registry() view returns (address)",
]);

export const actionRuleNames = ["UNSET", "MEMBERS", "ANYONE", "NOBODY"] as const;
export type ActionRuleName = (typeof actionRuleNames)[number];
