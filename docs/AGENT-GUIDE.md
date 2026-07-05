# SmartPolicy — Integration Guide

> Written for one-pass ingestion by a coding agent. Everything needed to
> integrate is in this file. No other document is required.

## Mental model (read this first)

SmartPolicy answers ONE question, everywhere:

```
isAllowed(policyId, subject, action) → bool
```

- A **policy** is data in the on-chain `PolicyRegistry` (immutable contract, no
  proxy): an owner, optional admins, a member set, per-action rules, optional
  expiry, optional free-form conditions.
- A **subject** is any address (an agent, a user, a contract).
- An **action** is a `bytes32` your application defines, by convention
  `keccak256("withdraw")` — plain names hashed.
- **Enforcement points** all consult the same answer:
  - Solidity: inherit `PolicyGate`, add one modifier.
  - Off-chain: call the MCP tool `policy_check` (identical answer).
  - High-risk ops: require a single-use signed **grant** on top (see Grants).

Changing who may do what = a registry transaction. The protected contract
never redeploys. Removing a member or disabling an action takes effect on the
very next call.

## Deployed addresses

| Network | Chain ID | PolicyRegistry | GrantVerifier |
|---|---|---|---|
| Ethereum Sepolia | 11155111 | `0x5D127b04d344EfBfb9C127F2B598Cb824D0B8334` | `0x3510B9427BeadD04D052E0b01248a6A6A1f23dc9` |

Source is verified on sepolia.etherscan.io at both addresses. Local dev: the
MCP package bootstraps any chain from embedded bytecode —

```bash
SMARTPOLICY_DEPLOYER_KEY=0x<funded key> \
SMARTPOLICY_RPC_URL=http://127.0.0.1:8545 \
npx smartpolicy-mcp deploy
# prints JSON: registry + verifier addresses and the exact env vars to run the server with
```

Fees on Sepolia (sent as exact `msg.value`, NOT minimum): `createPolicy` =
0.0001 ETH, every other write = 0.00001 ETH. Read them live via
`creationFee()` / `updateFee()` — they can change (capped at 0.01 / 0.001 ETH
forever). **Wrong msg.value reverts with `WrongFee(expected, provided)` — always
read the fee first, never hardcode it.**

## Enforcement map — what actually stops a call

Read this before designing a policy. Mechanisms differ in whether they have
teeth (revert the call) or merely inform:

| Mechanism | Teeth? | Enforced by |
|---|---|---|
| Membership + per-action rules | ✅ reverts on-chain | `isAllowed` via the gate |
| Expiry | ✅ everything answers false | `isAllowed` / verifier |
| Lock | ✅ freezes rule changes forever (enforcement continues) | registry |
| Grants (signature, single-use nonce, validity window, issuer authorization, policy/action binding) | ✅ reverts on-chain | `GrantVerifier` + gate |
| **Conditions** (`setCondition` key/value pairs) | ❌ **no teeth by themselves** | nobody on-chain — opaque bytes |
| Metadata (URI + hash) | ❌ informational only | never read by enforcement |

**Conditions get teeth ONLY through the grant path:** an issuer reads them
before signing (e.g. "maxDailySpend = 5 ETH" → issuer checks the day's total
and refuses to sign past it). On a function gated by `onlyAllowed` alone,
conditions are documentation, not enforcement. If a rule must be unbreakable,
express it as membership/action rules (on-chain teeth) or as an issuer check
on a grant-gated function (off-chain teeth, on-chain proof). Do NOT write
conditions and assume they enforce anything.

**Metadata trust:** `metadataURI` content can change behind an https URL even
after lock. For tamper-proof metadata use `ipfs://` (content-addressed) AND
set `metadataHash` (keccak256 of the document, stored on-chain) — then any
reader can verify the fetched document matches what the owner committed.
Always verify fetched metadata against `metadataHash` from `policy_get`.

## Quickstart A — protect a Solidity contract

Copy `PolicyGate.sol`, `IPolicyRegistry.sol`, `IGrantVerifier.sol` into your
project — in the distribution they ship under `vendor/` (with interfaces in
`vendor/interfaces/`, relative imports already correct); in the source repo
they live under `contracts/src/`.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PolicyGate} from "smartpolicy/PolicyGate.sol";

contract MyVault is PolicyGate {
    bytes32 public constant ACTION_WITHDRAW = keccak256("withdraw");
    uint256 public immutable policyId;

    // registry: PolicyRegistry address (table above)
    // grantVerifier: GrantVerifier address, or address(0) if you don't use grants
    // policyId_: the policy that governs this contract (create it first, Quickstart B)
    constructor(address registry, address grantVerifier, uint256 policyId_)
        PolicyGate(registry, grantVerifier)
    {
        policyId = policyId_;
    }

    function withdraw(address payable to, uint256 amount)
        external
        onlyAllowed(policyId, ACTION_WITHDRAW)   // ← the entire integration
    {
        (bool ok,) = to.call{value: amount}("");
        require(ok);
    }
}
```

Available modifiers (all revert with typed errors, see Errors):

| Modifier (exact signatures) | Gate |
|---|---|
| `onlyAllowed(uint256 policyId, bytes32 action)` | the canonical question — USE THIS by default. When a requirement says "only members may X", still use `onlyAllowed` with action "X": the default (UNSET) rule already means members-only, and the policy owner can later open/close that action with one registry tx. `onlyPolicyMember` ignores action rules and forfeits that control. |
| `onlyPolicyMember(uint256 policyId)` | membership only, ignores action rules |
| `onlyPolicyAdmin(uint256 policyId)` | policy admins + owner |
| `whenPolicyActive(uint256 policyId)` | policy exists and not expired |
| `withGrant(uint256 policyId, bytes32 action, IGrantVerifier.Grant calldata grant, bytes calldata signature)` | consumes a single-use signed grant (see Grants). The modifier itself pins the grant to THIS policyId and THIS action — a grant issued for a different action or policy reverts (`GrantActionMismatch` / `GrantPolicyMismatch`). |

The `Grant` struct is declared in `IGrantVerifier.sol` — import as
`import {IGrantVerifier} from "smartpolicy/interfaces/IGrantVerifier.sol";`
(both interfaces live under `contracts/src/interfaces/`, `PolicyGate.sol` under
`contracts/src/`; adjust the remapping prefix to wherever you vendored them).

`withGrant` does NOT imply an `isAllowed` check — stack `onlyAllowed(...)`
BEFORE `withGrant` when the action should also pass the policy rules (that
order means a policy denial reverts before the grant nonce is touched), or use
`withGrant` alone when the issuer's off-chain approval IS the whole rule.

## Quickstart B — create and manage a policy

Every write goes to `PolicyRegistry` and must include the exact fee as
`msg.value`. The wallet that calls `createPolicy` becomes the policy owner.

```solidity
// direct calls (cast / viem / ethers all work the same)
uint256 fee = registry.creationFee();
uint256 policyId = registry.createPolicy{value: fee}(
    0,        // flags: 0 = closed membership; 1 = FLAG_OPEN_MEMBERSHIP (everyone
              //        is a member); 2 = FLAG_TRANSFERABLE (ownership movable)
    0,        // expiresAt unix seconds; 0 = never
    "ipfs://my-policy-description",  // metadataURI, informational only
    keccak256(metadataJsonBytes)     // metadataHash: on-chain commitment to the
                                     // metadata document; bytes32(0) = none
);
// policyId is also emitted: event PolicyCreated(uint256 indexed policyId, ...)

uint256 ufee = registry.updateFee();
address[] memory agents = new address[](1);
agents[0] = 0xYourAgentAddress;
registry.addMembers{value: ufee}(policyId, agents);

// per-action refinement (overrides membership for that action only):
// rule: 0=UNSET (members; the default), 1=MEMBERS (explicit), 2=ANYONE, 3=NOBODY
registry.setActionRule{value: ufee}(policyId, keccak256("deposit"), IPolicyRegistry.ActionRule.ANYONE);
registry.setActionRule{value: ufee}(policyId, keccak256("sweep"), IPolicyRegistry.ActionRule.NOBODY);
```

Or use the MCP tools `policy_create` / `policy_update` — they return unsigned
`{to, value, data}` transactions for your wallet to sign (the server never
holds keys).

Policy ids are sequential starting at 1. After `createPolicy`, read the new id
from the return value or from the receipt's `PolicyCreated` event — full
signature: `event PolicyCreated(uint256 indexed policyId, address indexed
owner, uint8 flags, uint64 expiresAt)` (policyId is `topics[1]`).

**Complete registry write surface** (human-readable ABI — usable directly with
viem `parseAbi` / `cast`; all payable ones take exact `updateFee()` as value,
except `createPolicy` which takes `creationFee()`; `lockPolicy` and
`transferPolicyOwnership` take no value):

```
function createPolicy(uint8 flags, uint64 expiresAt, string metadataURI, bytes32 metadataHash) payable returns (uint256)
function addMembers(uint256 policyId, address[] members) payable
function removeMembers(uint256 policyId, address[] members) payable
function setActionRule(uint256 policyId, bytes32 action, uint8 rule) payable
function addIssuer(uint256 policyId, address issuer) payable
function removeIssuer(uint256 policyId, address issuer) payable
function addAdmin(uint256 policyId, address admin) payable
function removeAdmin(uint256 policyId, address admin) payable
function setCondition(uint256 policyId, bytes32 key, bytes value) payable
function clearCondition(uint256 policyId, bytes32 key) payable
function setExpiry(uint256 policyId, uint64 expiresAt) payable
function setMetadataURI(uint256 policyId, string metadataURI, bytes32 metadataHash) payable
function lockPolicy(uint256 policyId)
function transferPolicyOwnership(uint256 policyId, address newOwner)
```

**Read surface** (free view calls, same human-readable ABI form):

```
function isAllowed(uint256 policyId, address subject, bytes32 action) view returns (bool)
function isPolicyActive(uint256 policyId) view returns (bool)
function isMember(uint256 policyId, address account) view returns (bool)
function isAdmin(uint256 policyId, address account) view returns (bool)
function isOwner(uint256 policyId, address account) view returns (bool)
function isAuthorizedIssuer(uint256 policyId, address issuer) view returns (bool)
function getPolicy(uint256 policyId) view returns ((address owner, uint64 expiresAt, uint8 flags, bool locked, bytes32 metadataHash, string metadataURI))
function getActionRule(uint256 policyId, bytes32 action) view returns (uint8)
function getCondition(uint256 policyId, bytes32 key) view returns (bytes)
function memberCount(uint256 policyId) view returns (uint256)
function policyCount() view returns (uint256)
function creationFee() view returns (uint256)
function updateFee() view returns (uint256)
```

Authorization matrix for registry writes:

| Operation | Who may call |
|---|---|
| `addMembers` `removeMembers` `setActionRule` `addIssuer` `removeIssuer` `setCondition` `clearCondition` `setExpiry` `setMetadataURI` | owner or admin |
| `addAdmin` `removeAdmin` `lockPolicy` `transferPolicyOwnership` | owner only |

`lockPolicy` is **irreversible**: rules freeze forever, but the policy keeps
enforcing (a locked policy is a credible commitment, not a kill switch).
`transferPolicyOwnership` requires FLAG_TRANSFERABLE set at creation.
Expired policies answer `false` to everything; un-expire via `setExpiry`
(unless locked).

## Quickstart C — grants (off-chain approval for high-risk actions)

A grant is a short-lived, single-use EIP-712 authorization signed by an
**issuer** the policy owner registered via `addIssuer`. Use it when an action
needs fresh off-chain approval (KYC check, anomaly screening, human sign-off)
on every call.

Flow:
1. Policy owner: `registry.addIssuer{value: ufee}(policyId, issuerAddress)`.
2. Subject asks the issuer (e.g. MCP tool `grant_issue`) for a grant for
   (policyId, subject, action). The issuer applies its own checks and signs.
3. Subject calls the protected function, passing grant + signature. The gate
   checks policyId/action/subject binding; the verifier checks signature,
   validity window, issuer authorization, policy active — then consumes the
   nonce. A grant admits exactly ONE successful call. If the transaction
   reverts for any reason, nonce consumption rolls back with it — the grant
   remains redeemable until it expires.

```solidity
function emergencyDrain(
    address payable to,
    IGrantVerifier.Grant calldata grant,
    bytes calldata signature
)
    external
    withGrant(policyId, keccak256("emergencyDrain"), grant, signature)
{
    // runs only with a fresh, single-use, issuer-signed approval
}
```

Grant struct (EIP-712, domain `{name: "SmartPolicy Grants", version: "1",
chainId, verifyingContract: <GrantVerifier>}`; exact EIP-712 type string for
off-doc signers:
`Grant(uint256 policyId,address subject,bytes32 action,uint64 issuedAt,uint64 expiresAt,uint256 nonce,address issuer,address target)`):

```solidity
struct Grant {
    uint256 policyId;
    address subject;    // must equal msg.sender of the protected call
    bytes32 action;
    uint64  issuedAt;
    uint64  expiresAt;  // keep short: minutes
    uint256 nonce;      // single-use per issuer; random 256-bit recommended
    address issuer;
    address target;     // the ONLY contract allowed to consume this grant
}
```

`target` binds the grant to the integrator contract that will redeem it: the
verifier requires `msg.sender == grant.target` in `consumeGrant`. This stops a
third party from reading a broadcast grant out of the mempool and burning its
nonce to grief the gated action. When issuing, set `target` to the contract
whose `withGrant` function you will call.

## MCP server

Packaged (Node ≥ 20): install the package `@smartpolicy/mcp` (tarball or
registry — note the scope; the executable it installs is named
`smartpolicy-mcp`), then:

```bash
npx smartpolicy-mcp            # zero config = public Ethereum Sepolia deployment
npx smartpolicy-mcp deploy     # bootstrap the protocol onto a fresh chain (see "Deployed addresses")
```

(Shell examples in this guide are bash-style; on Windows, translate env-var
prefixes to your shell or use Git Bash.)

It speaks MCP over stdio — point any MCP client at the command, or drive it
directly with newline-delimited JSON-RPC (`initialize` → `notifications/initialized`
→ `tools/call`). The authoritative input schema for every tool (exact JSON
shapes, optional fields, enums) is returned by the standard MCP `tools/list`
request — prefer that over guessing from the tables here.

Custom deployment (local anvil, other networks) via env vars:

```bash
SMARTPOLICY_RPC_URL=http://127.0.0.1:8545 \
SMARTPOLICY_CHAIN_ID=31337 \
SMARTPOLICY_REGISTRY=0x...    # required together \
SMARTPOLICY_VERIFIER=0x...    # required together \
SMARTPOLICY_ISSUER_KEY=0x...  # optional; enables grant_issue \
npx smartpolicy-mcp
```

| Tool | Input | Returns |
|---|---|---|
| `policy_check` | policyId, subject, action | `{allowed, exists, reasons[]}` — same answer as on-chain |
| `policy_get` | policyId | `exists`, owner, expiry, active, locked, membership mode, member count, metadataURI, metadataHash (verify fetched metadata against this) |
| `policy_fees` | — | `{creationFeeWei, updateFeeWei}` — read before building any write tx |
| `grant_issuer_info` | — | this server's issuer address + limits |
| `grant_issue` | policyId, subject, action, target, ttlSeconds | signed grant + `castTuple` (8-field, paste-ready for `cast send`) + `grantedTtlSeconds`/`ttlClamped` + usage |
| `grant_verify` | grant, signature | `{valid, nonceUsed}` — pre-flight a grant before broadcasting |
| `policy_create` | openMembership?, transferable?, expiresAt?, metadataURI?, metadataHash? | unsigned tx `{to, value, data}` — you sign |
| `policy_update` | policyId + operation (below) | unsigned tx `{to, value, data}` — you sign |

`policy_update` takes a top-level `policyId` plus a nested `operation` object
discriminated on `kind`. Exact shape:

```json
{ "policyId": "5",
  "operation": { "kind": "removeMembers", "members": ["0xDdD..."] } }
```

Operation kinds: `addMembers`/`removeMembers` (`members: address[]`) ·
`setActionRule` (`action`, `rule: "UNSET"|"MEMBERS"|"ANYONE"|"NOBODY"`) ·
`addIssuer`/`removeIssuer` (`issuer`) · `addAdmin`/`removeAdmin` (`admin`) ·
`setExpiry` (`expiresAt`). Registry writes with no MCP kind (`setCondition`,
`clearCondition`, `setMetadataURI`, `lockPolicy`, `transferPolicyOwnership`)
require direct contract calls — signatures in the write surface above.

`grant_issue` refuses to sign unless (a) this server's issuer address is
authorized for the policy and (b) `policy_check` answers allowed=true for the
(subject, action) — the issuer never overrides the policy. Composition
consequence: to grant a NON-member, the action's rule must be ANYONE (or add
them as a member first); grants add an approval layer on top of the policy,
never a bypass of it. `ttlSeconds` is clamped to the server's
`maxGrantTtlSeconds` (default 3600 — read `grant_issuer_info`; the schema
ceiling of 86400 only applies if the server is configured that high).

Actions in MCP tools accept plain names ("withdraw") — hashed automatically to
match `keccak256("withdraw")` — or raw `0x…` bytes32 passed through.

## Reference

**isAllowed truth table** (policy active; otherwise always false):

| Action rule | Member | Non-member |
|---|---|---|
| UNSET (default) | ✅ | ❌ |
| MEMBERS | ✅ | ❌ |
| ANYONE | ✅ | ✅ |
| NOBODY | ❌ | ❌ |

FLAG_OPEN_MEMBERSHIP makes every address a member (so UNSET/MEMBERS → ✅ for all).

**Errors** (full signatures — enough to decode any revert without the ABIs):

Registry: `WrongFee(uint256 expected, uint256 provided)` ·
`PolicyNotFound(uint256 policyId)` · `PolicyIsLocked(uint256 policyId)` ·
`NotPolicyOwner(uint256 policyId, address caller)` ·
`NotPolicyOwnerOrAdmin(uint256 policyId, address caller)` ·
`PolicyNotTransferable(uint256 policyId)` · `ZeroAddress()`

Gate: `NotAllowedByPolicy(uint256 policyId, address subject, bytes32 action)` ·
`NotPolicyMember(uint256 policyId, address subject)` ·
`NotPolicyAdmin(uint256 policyId, address subject)` ·
`PolicyNotActive(uint256 policyId)` · `GrantVerifierNotConfigured()` ·
`GrantNotForCaller(address subject, address caller)` ·
`GrantPolicyMismatch(uint256 expected, uint256 actual)` ·
`GrantActionMismatch(bytes32 expected, bytes32 actual)`

Verifier (all parameterless): `GrantExpired()` · `GrantNotYetValid()` ·
`GrantNonceUsed()` · `GrantIssuerNotAuthorized()` · `GrantSignatureInvalid()` ·
`GrantPolicyInactive()` · `GrantTargetMismatch()` (caller is not the grant's
bound `target`)

`PolicyGate` constructor: `RegistryMismatch(address gateRegistry, address
verifierRegistry)` — the gate's registry and the verifier's registry differ;
fix the addresses you pass to the constructor.
`PolicyRegistry` admin: `FeeAboveCap(uint256 fee, uint256 cap)`,
`FeeTransferFailed()`; the gate constructor also reverts with the string
`"registry is zero"`.

NOTE: the verifier and `isGrantValid` do NOT check the grant's `subject` —
subject binding is the gate's job (`GrantNotForCaller`). Any off-chain consumer
of `isGrantValid` must independently confirm presenter == `grant.subject`.

Note on grant timestamps: `issuedAt`/`expiresAt` are checked against
`block.timestamp`. The MCP issuer backdates `issuedAt` by a 60s buffer so a
just-issued grant is immediately valid on chains whose latest block lags real
time (e.g. ~12s blocks on Sepolia). If you sign grants yourself, do the same —
setting `issuedAt` to the exact wall-clock now can transiently revert
`GrantNotYetValid` until the chain's timestamp catches up.

| Common revert | Meaning / fix |
|---|---|
| `WrongFee` | read `creationFee()`/`updateFee()` and send exactly that |
| `NotAllowedByPolicy` | the gate said no — check `policy_check` reasons |
| `PolicyIsLocked` | rules frozen forever; create a new policy |
| `GrantIssuerNotAuthorized` | policy owner must `addIssuer` first |
| `GrantNotForCaller` | grants bind to msg.sender; the subject must submit the tx |

**Footguns:**
- Fees are exact-match, not minimum. Read before sending — overpaying reverts
  just like underpaying.
- `isAllowed` returns `false` (no revert) for nonexistent/expired policies —
  check `policy_get` if you expected `true`.
- Action ids are case-sensitive pre-hash: `keccak256("Withdraw")` ≠
  `keccak256("withdraw")`. Pick ONE exact string per action (any casing) and
  use it identically in the contract, the registry rules, and MCP calls.
- Grants: `subject` must be the eventual `msg.sender`. An agent cannot redeem
  a grant issued to another address (`GrantNotForCaller`).
- To temporarily disable an action use rule NOBODY; to restore, set UNSET or
  MEMBERS — they are functionally identical (see truth table).
- Conditions (`setCondition`) are opaque bytes the registry stores but never
  evaluates — they do NOT affect `isAllowed`. They exist for off-chain
  enforcement points (issuers, backends) that read and interpret them by
  their own conventions. Condition KEYS follow the same convention as
  actions: `keccak256("maxDailySpend")` for a named key (0x-bytes32 passes
  through). Values: abi-encode them (e.g. `abi.encode(uint256(5 ether))`)
  and document your encoding in the policy metadata.
- With FLAG_OPEN_MEMBERSHIP, `removeMembers` only edits the explicit member
  set — every address still counts as a member while the flag is set; the
  flag is fixed at creation. Use action rules (NOBODY) to restrict an open
  policy.
- The registry protocol owner can change fees (within hard caps) and nothing
  else. Policy data is untouchable by anyone but the policy's own owner/admins.
