# SmartPolicy MCP Server

The interface AI agents use to consume the protocol. TypeScript, official MCP SDK,
viem for chain access. Also exposes the same surface as REST for non-MCP clients.

## Tool surface (v0 target)

| Tool | Description | Pricing |
|---|---|---|
| `policy_check` | "May subject S perform action A under policy N?" → allow/deny + reasons. Maps 1:1 to `PolicyRegistry.isAllowed` — same answer on-chain and off | free |
| `policy_get` | Policy metadata, members, admins, issuers, action rules, conditions | free |
| `grant_issue` | Issue an EIP-712 signed grant (server must be an authorized issuer for the policy) | x402 (USDC per call) |
| `policy_create` | Build the create-policy transaction; either submit it or return calldata for the caller's own wallet to sign | x402 + on-chain fee |
| `policy_update` | Membership / condition / expiry changes, same pattern | x402 + on-chain fee |

## Auth & payments

- Session auth: SIWE (EIP-4361). No bare address headers — possession of the key
  must be proven by signature.
- Metering: x402 (HTTP 402 payment flow, USDC on Base) on the paid tools.
- Self-hosting is supported and documented; a self-hosted server registers its own
  issuer address on the policies it serves. The hosted instance has no protocol
  privileges.

## State

- Event index of the Registry (SQLite to start) — the server never scans chain
  state on the hot path.
- Nonce issuance for grants.
- No custody of user funds, ever. The server's only key is its grant-issuer key.

## Status

**v0 packaged and field-tested (stdio transport).** Tools: `policy_check`,
`policy_get`, `grant_issue` (returns a paste-ready `castTuple`),
`grant_issuer_info`, `policy_create`, `policy_update`. Plus a CLI subcommand:
`npx smartpolicy-mcp deploy` bootstraps PolicyRegistry + GrantVerifier on any
chain from bytecode embedded in the package. Zero-config default targets the
public Ethereum Sepolia deployment. Write tools return unsigned calldata —
this server never holds user keys; its only key is the optional grant-issuer
key. Validated by two unaided fresh-agent execution tests (see PLAN.md
decision log, 2026-06-12).

**HTTP transport + x402 metering shipped (2026-07-05):** `smartpolicy-mcp serve`
runs Streamable HTTP (stateless) on `SMARTPOLICY_PORT` (default 3402):
`POST /mcp` + `GET /healthz`. Setting `SMARTPOLICY_X402_PAY_TO` enables x402
metering (USDC, `exact` scheme) on `grant_issue`/`policy_create`/`policy_update`
only — reads are always free. Price via `SMARTPOLICY_X402_PRICE_USDC`
(default 0.001); facilitator via `SMARTPOLICY_X402_FACILITATOR` (default
`https://x402.org/facilitator`, keyless testnet — use a CDP facilitator for
mainnet). Smoke test: `npm run smoke:http` against a running server.
Remaining: SIWE sessions, event indexer, settled-payment e2e test.

Windows note: never call `process.exit()` while viem keep-alive sockets are
open — libuv UV_HANDLE_CLOSING assertion crash; let the event loop drain.

## Running

```bash
npm install
SMARTPOLICY_RPC_URL=...        # default http://127.0.0.1:8545
SMARTPOLICY_CHAIN_ID=...       # default 31337
SMARTPOLICY_REGISTRY=0x...     # required: PolicyRegistry address
SMARTPOLICY_VERIFIER=0x...     # required: GrantVerifier address
SMARTPOLICY_ISSUER_KEY=0x...   # optional: enables grant_issue
npm start
```

Claude Code / MCP client config:

```json
{
  "mcpServers": {
    "smartpolicy": {
      "command": "npx",
      "args": ["tsx", "<path>/mcp/src/index.ts"],
      "env": { "SMARTPOLICY_REGISTRY": "0x...", "SMARTPOLICY_VERIFIER": "0x..." }
    }
  }
}
```

## End-to-end integration test

With anvil running and contracts deployed (`contracts/script/Deploy.s.sol`):

```bash
npm run integration
```

Proves the full loop: create policy → membership/action-rule checks → issue an
EIP-712 grant in TypeScript → verify + consume it on-chain → replay rejected →
revocation is instant. This also pins the EIP-712 domain compatibility between
`src/grants.ts` and `GrantVerifier.sol` — if either side changes, this fails.

## Implementation notes

- `policyId` tool inputs are string/number, never JSON-Schema-incompatible
  bigint (a bigint zod schema silently breaks `tools/list` in the MCP SDK).
- Actions are plain names ("withdraw") hashed with keccak256, matching the
  `keccak256("withdraw")` convention in protected contracts; 0x-prefixed
  bytes32 values pass through unchanged.
