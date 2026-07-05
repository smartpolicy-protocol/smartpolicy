# SmartPolicy

**Runtime authorization for AI agents and smart contracts.**

Define what an agent, a user, or a contract is allowed to do — once, as a policy.
Enforce it everywhere: on-chain via a minimal verifier, off-chain via an MCP server
and REST API that AI systems consume directly. Update the rules without redeploying
anything.

> Status (2026-06-12): core contracts live on Ethereum Sepolia
> (Etherscan-verified, addresses in contracts/deployments/sepolia.json); 54
> Foundry tests green; MCP server v0 packaged — `npx smartpolicy-mcp` runs
> zero-config against Sepolia, `npx smartpolicy-mcp deploy` bootstraps any
> chain from embedded bytecode; AI-consumability proven by unaided
> fresh-agent execution tests (incl. cold start on an empty chain). NOT
> audited; internal until mature — no public repo or registry listings yet.
> Current state, decisions, and how to resume work: PLAN.md.

## Why

Every team shipping AI agents hits the same wall: the agent can technically do
anything its keys allow, and the only ways to constrain it are hardcoded prompts or
redeployed code. Every smart contract team hits the mirror image: access rules baked
into the contract at deploy time.

SmartPolicy separates the **rule** from the **enforcement point**:

- A **policy** lives in the on-chain Registry: members, admins, conditions, expiry,
  and mutability flags. It is data, not code. Changing a rule is a transaction, not
  a redeploy.
- **Enforcement** happens wherever the action happens:
  - A smart contract inherits one modifier and checks the Registry (free view call).
  - An AI agent (or the service in front of it) asks the MCP server / REST API:
    *"may `0xAgent` perform `action` under policy `N`?"* and receives a short-lived
    **signed grant** (EIP-712) that any contract or backend can verify.

## What this is NOT

- Not a token. There is no protocol token, no ICO, no governance theater.
  Revenue is fees: a small fee on on-chain policy writes, and metered (x402)
  pay-per-call on the hosted API. Reads and verification are free.
- Not upgradeable. The core Registry is immutable once deployed. Trust comes from
  code you can read, not admin keys you have to trust. New protocol versions are
  new deployments.
- Not an oracle. SmartPolicy answers "is this allowed?", not "what happened in the
  world?". Condition values that depend on external facts are attested via signed
  grants from sources the policy owner chooses.

## Architecture (short version)

```
┌─────────────┐   MCP / REST (x402 metered)   ┌──────────────────┐
│  AI agents   │ ────────────────────────────▶ │ SmartPolicy MCP  │
│  & services  │ ◀──── signed grants ────────  │ server (TS)      │
└─────────────┘                                └────────┬─────────┘
                                                        │ reads + grant issuance
┌─────────────┐   inherit Gate modifier        ┌────────▼─────────┐
│  Protected   │ ────── view calls ──────────▶ │ PolicyRegistry   │
│  contracts   │                               │ (Base, immutable)│
└─────────────┘                                └──────────────────┘
```

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full design and the rationale for
every decision (chain, fees, trust model, what was deliberately dropped from v1).

## Repository layout

```
contracts/   Solidity core: PolicyRegistry, PolicyGate, interfaces (Foundry)
mcp/         MCP server + REST API (TypeScript, x402 metering)
sdk/         TypeScript client SDK (planned)
docs/        Integration guides (planned)
```

## Lineage

SmartPolicy is a clean rewrite of the strongest ideas from a 2025 prototype
("Smart Policy Protocol", Sepolia): the policy registry, the tiered integration
model, and hybrid on-chain + signed-token enforcement. The rewrite deliberately
drops the SPOL token/ICO/governance suite, the sports-prediction oracle, the
factory contracts, and the upgradeable-proxy trust model, and fixes the known
security issues (tx.origin checks, missing reentrancy guards, header-only API auth).

## License

Apache-2.0 — see [LICENSE](./LICENSE).
