# SmartPolicy — Architecture & Decisions

This document records the design and the *why* behind each decision, so the project
can be picked up cold (by a human or an AI) without re-deriving the reasoning.

## 1. Product definition

SmartPolicy is an authorization layer with three consumers:

1. **AI agents / MCP clients** — the primary audience. They call the MCP server
   ("may I do X under policy N?") and receive yes/no plus, when needed, a signed
   grant they can hand to a downstream system as proof.
2. **Backends / APIs** — verify grants (one EIP-712 signature check) instead of
   building their own permission system.
3. **Smart contracts** — inherit `PolicyGate`, get `onlyPolicyMember(policyId)`-style
   modifiers backed by free Registry view calls.

One policy, three enforcement points. The pitch in one line:
**"Change what your agents and contracts are allowed to do without redeploying them."**

## 2. On-chain core

### PolicyRegistry (immutable, Base)

Single contract holding all policies. No proxies, no upgrade path.

A policy:

```
struct Policy {
    address owner;
    uint64  expiresAt;        // 0 = never
    uint8   flags;            // bitfield: OPEN_MEMBERSHIP, TRANSFERABLE
    bool    locked;           // irreversibly frozen rules (still enforceable)
    string  metadataURI;      // off-chain description (IPFS/HTTPS), not enforced
}
```

Per policy: a member set, an admin set, an authorized-issuer set (for grants, §3),
per-action rules, and a condition map (`bytes32 key => bytes value` with a
typed-value convention in the SDK). Conditions are data the policy owner
maintains; enforcement points read them and decide. The Registry never interprets
condition semantics — that keeps the core small, auditable, and future-proof.

**The canonical question.** Everything consuming the protocol — agents, the MCP
server, backends, contracts — asks one general question:

```
isAllowed(policyId, subject, action) → bool
```

Membership is the default answer; per-action rules refine it without changing the
question: `ActionRule = UNSET (→ members) | MEMBERS | ANYONE | NOBODY`. This keeps
the agent-facing surface uniform — new authorization semantics are new rules
behind the same call, never new entry points.

Write operations (owner/admin only): create policy, add/remove members, admins and
issuers, set action rules and conditions, lock policy (irreversible), transfer
ownership (if flag allows). Every write emits an event — the MCP server indexes
events rather than polling state. The protocol owner's only powers are fee
parameters (hard-capped by immutables set at deploy) and the fee collector
address — never policy data.

**Decisions and rationale:**

- **Immutable, not UUPS.** The v1 prototype was upgradeable; that is the single
  biggest reason serious integrators would refuse to put it in their auth path
  (the proxy admin can change the rules of the rule system). Immutability converts
  "trust the team" into "read the code". Protocol evolution = deploy
  RegistryV2 + a one-way migration helper.
- **No factories.** v1 deployed a wrapper contract per policy — gas-heavy and
  pointless. One registry, integer policy IDs.
- **`msg.sender` only.** v1 used `tx.origin` for owner checks through its facade
  contract; that is a relay-attack surface and is gone along with the facade itself.
- **Policy IDs start at 1.** v1 started at 220,000 for no documented reason.

### PolicyGate (abstract contract integrators inherit)

~80 lines. Holds the Registry + GrantVerifier addresses (immutable), exposes modifiers:

- `onlyAllowed(uint256 policyId, bytes32 action)` — the canonical question as a modifier
- `onlyPolicyMember(uint256 policyId)`
- `onlyPolicyAdmin(uint256 policyId)`
- `whenPolicyActive(uint256 policyId)`
- `withGrant(uint256 policyId, bytes32 action, Grant calldata g, bytes calldata sig)` —
  consumes an EIP-712 signed grant (see §3). The gate pins the grant to the
  given policyId/action — without this binding a grant issued for one action
  could redeem against another (found via doc-driven agent testing, 2026-06-12).

Integration is: inherit, pass registry address to the constructor, add modifiers.
Same DX as the v1 prototype's best part (the ~90-line example app), which is the
thing worth keeping. See `contracts/src/examples/AgentGuardedTreasury.sol`.

### GrantVerifier (standalone immutable contract)

EIP-712 typed data:

```
Grant {
    uint256 policyId;
    address subject;      // who is allowed
    bytes32 action;       // what they may do (app-defined)
    uint64  issuedAt;
    uint64  expiresAt;    // short-lived: minutes, not days
    uint256 nonce;        // single-use, namespaced per issuer
    address issuer;       // must be an authorized issuer for the policy
}
```

Policy owners register issuer addresses in the Registry (`addIssuer`/`removeIssuer`
— first-class, not a condition convention). The hosted MCP server is one possible
issuer; self-hosted issuers are equally valid — the protocol does not privilege
the hosted service.

Fixes vs v1's TokenVerifier: proper EIP-712 (chain-bound, contract-bound domain),
mandatory single-use nonces namespaced per issuer (no issuer can burn another's
nonce space), no reliance on user-supplied timestamps alone.

## 3. Off-chain layer: MCP server + REST API

TypeScript, official MCP SDK, viem for chain access. Stateless except for an event
index (SQLite/Postgres) and nonce issuance.

MCP tools (initial surface):

| Tool | What it does | Paid? |
|---|---|---|
| `policy_check` | "may subject S do action A under policy N?" → boolean + reasons | free |
| `policy_get` | policy metadata, members, conditions | free |
| `grant_issue` | issue an EIP-712 grant (server is an authorized issuer) | x402 |
| `policy_create` | build + submit the create-policy tx (or return calldata for the agent to sign) | x402 + on-chain fee |
| `policy_update` | membership/condition changes, same pattern | x402 + on-chain fee |

The same surface is exposed as REST for non-MCP consumers. Auth for the API is
SIWE (EIP-4361) — wallet signs a session, no spoofable address headers (the v1
backend's fatal flaw).

**Why MCP-first:** the user-facing thesis is that agents, not humans, will be the
main consumers. MCP is the de facto integration standard for that world; a UI can
come later and call the same API.

## 4. Fees — no token

Two meters, both denominated in real money:

1. **On-chain protocol fee** on Registry *writes* only (create/update), payable in
   ETH on Base, forwarded to a plain fee-collector address. Small and flat
   (target: cents-equivalent). Views are free — adoption depends on free reads.
2. **x402 metering** on the hosted MCP/REST service for grant issuance and
   tx-building convenience. Agents pay per call in USDC via the HTTP 402 flow.
   Self-hosting the server is allowed and documented; the hosted service competes
   on convenience and uptime, not lock-in.

Explicitly dropped from v1: SPOL token, ICO manager, vesting, governance, and
token-holder fee discounts. Reasons: regulatory exposure, credibility cost,
maintenance surface, and none of it was necessary for value capture.

## 5. Chain choice

**Base** (mainnet) / **Base Sepolia** (test). Rationale: sub-cent writes, native
USDC, the x402/agent-payments ecosystem is centered there, and EVM keeps the
contracts portable. The Registry is chain-agnostic Solidity; deploying to other
EVM chains later is a config change, but v2 launches on exactly one chain to keep
the trust story simple ("the registry is at one address; verify it").

## 6. Tooling & quality bar

- **Contracts:** Foundry (forge test/fuzz), Solidity ^0.8.24, OpenZeppelin 5.x
  (non-upgradeable variants only). CI runs tests + slither on every push.
- **Tests are not optional.** v1 shipped zero tests; that alone disqualified it.
  Target: full unit coverage on Registry/Gate/GrantVerifier, fuzz on membership
  and grant verification, invariant tests on fee accounting.
- **Server:** TypeScript, strict mode, vitest.
- **Transparency:** public repo, verified contracts on Basescan, deployment
  addresses committed to `deployments/`, CHANGELOG, audit before mainnet (not
  before — an audit of unreviewed scope is wasted money).

## 7. What we deliberately did NOT bring over from v1

| v1 component | Verdict | Why |
|---|---|---|
| UUPS upgradeable core | dropped | trust blocker; immutable core instead |
| SPOL token / ICO / vesting / governance | dropped | fee model replaces it |
| Sports predictions + TheOdds resolver | dropped | centralized oracle, off-thesis |
| Per-policy factory contracts | dropped | gas waste; one registry |
| .NET backend | replaced | TS MCP server; SIWE auth instead of address headers |
| Angular policy UI + docs site | deferred | API/MCP first; the docs *content* is worth reusing |
| Tiered integration model + minimal protector interface | **kept** | the genuinely good DX |
| Hybrid on-chain + signed-token enforcement | **kept** (as EIP-712 grants) | the genuinely good idea |

## 8. Roadmap

1. **Core contracts** — Registry, Gate, GrantVerifier + full Foundry test suite.
2. **MCP server** — read tools first (`policy_check`, `policy_get`), then grant
   issuance, then x402 metering.
3. **Base Sepolia deployment** + example integrations (one contract, one agent).
4. **Public repo** + docs (reuse v1 docs content, rewritten for the new surface).
5. **Audit → Base mainnet** — only after steps 1–4 and only if there is real usage
   on testnet. Do not pay for an audit before someone wants this.
