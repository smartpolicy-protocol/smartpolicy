# SmartPolicy — Multi-Agent Review & Remediation (2026-06-12)

A multi-agent workflow reviewed the whole project across four dimensions
(contract security, test coverage, MCP server, doc-vs-code drift). Every finding
was adversarially verified by an independent skeptic before counting. Result:
**14 confirmed defects, 22 ideas**. No fund-loss or access-control bypass was
found. This document records each finding and what we did about it.

## Headline outcome

- **All 14 confirmed defects are fixed** (contracts, MCP, tests, docs).
- **7 high-value, low-risk ideas implemented.**
- Tests grew **55 → 73** (all green). MCP tools grew **6 → 8**.
- Two contract fixes (M1, L1) required a code change; we took the redeploy now
  (internal/testnet, no external integrators) rather than deferring.
- One fix uncovered a **real staleness bug we then fixed** (viem caches
  `getBlockNumber`; pinning reads to a cached block missed just-mined updates).

## Confirmed defects — status

| ID | Severity | Area | What was wrong | Fix | Done |
|----|----------|------|----------------|-----|------|
| M1 | medium | contract | `consumeGrant` was permissionless → a mempool front-runner could burn a grant's nonce and grief the gated action (DoS, no fund loss) | Added `target` field to `Grant`; verifier requires `msg.sender == grant.target` | ✅ redeploy |
| M2 | medium | MCP | EIP-712 domain `chainId` from env was never reconciled with the live RPC → grants silently unverifiable; `grant_issue` reports success on a tuple that always reverts | `assertChainId()` on startup + before every `grant_issue` | ✅ |
| L1 | low | contract | `PolicyGate` accepted registry + verifier independently; a mismatch governs membership and grants against different policy universes (unrecoverable, both immutable) | Constructor asserts `verifier.registry() == registry` when grants used; `RegistryMismatch` error | ✅ redeploy |
| L2 | low | test | `onlyPolicyAdmin`/`onlyPolicyMember`/`whenPolicyActive` had zero coverage | `GateHarness` + 5 tests (owner/admin/member/outsider/expiry) | ✅ |
| L3 | low | test | `setFeeCollector` untested | 3 tests (routes withdrawal, rejects zero, only-owner) | ✅ |
| L4 | low | test | `withdrawFees` reverting-collector path untested | `RejectEther` test proving funds surface the revert and stay recoverable | ✅ |
| L5 | low | test | grant validity-window boundaries untested | 4 boundary tests at exact `issuedAt`/`expiresAt` ±1s | ✅ |
| L6 | low | MCP | numeric env vars parsed with `Number()` → silent `NaN` corrupting domain/TTL | `parsePositiveInt` rejects NaN/garbage | ✅ |
| L7 | low | MCP | malformed `SMARTPOLICY_ISSUER_KEY` crashed the whole server (killed free reads too) | shape-validate; malformed → warn + disable issuance, reads keep working | ✅ |
| L8 | low | MCP | `deploy` asserted `contractAddress` non-null without checking receipt `status` → null address in success-shaped output | throw on `status !== 'success'` | ✅ |
| L9 | low | doc | guide listed `GrantSubjectMismatch()` (never thrown) as a verifier revert | removed; added note that the verifier does NOT check subject (gate's job) | ✅ |
| N1 | nit | test | action-rule precedence over `FLAG_OPEN_MEMBERSHIP` untested | combined open-membership + NOBODY/ANYONE test | ✅ |
| N2 | nit | MCP | `policy_check` reasons from 4 non-atomic reads could cosmetically race | pinned all reads to one (uncached) block | ✅ |
| N3 | nit | doc | error reference omitted `FeeAboveCap`/`FeeTransferFailed`/`"registry is zero"` | added all three (+ the new `GrantTargetMismatch`/`RegistryMismatch`) | ✅ |

## Ideas implemented now (low-risk, high-value)

1. **`grant_verify` tool** (idea #2) — off-chain pre-flight of a grant
   (`isGrantValid` + `isNonceUsed`) so an agent confirms validity before
   broadcasting instead of eating a revert.
2. **`policy_fees` tool** (idea #3) — exposes `creationFee`/`updateFee`; the
   `WrongFee` footgun was the most-emphasized yet had no read tool.
3. **MCP server `instructions`** (idea #4) — a 6-line mental model delivered
   in-band on `initialize` (read fee first; conditions have no teeth; subject ==
   msg.sender; writes are unsigned).
4. **`exists` field** (idea #6) on `policy_check`/`policy_get`, and the reason
   now distinguishes "does not exist" from "expired".
5. **TTL transparency** (idea #7) — `grant_issue` returns
   `requestedTtlSeconds`/`grantedTtlSeconds`/`ttlClamped`.
6. **8-field `castTuple`** stays paste-ready for the new `target` grant shape.
7. **`getPolicy` no longer reverts** on unknown ids — returns `exists:false`.

## Deferred (recorded in PLAN.md "Pre-redeploy design items")

- **Condition-checker hooks** (`IConditionChecker`, restrict-only) — the
  on-chain answer to "conditions have no teeth"; large, real attack surface,
  must be designed before a redeploy.
- **On-chain `multicall` with summed-fee accounting** — atomic provisioning;
  touches fee/reentrancy/`msg.value`-reuse; redeploy.
- **EIP-1271 issuer signatures** — sequence with the TEE/HSM issuer-key
  mainnet blocker.
- **Event-query / history MCP tool** — order behind the dedicated indexer.
- **ERC-8004 agent-identity members** — defer until external pull.

## Explicitly checked and found SOUND

- No fund-loss or access-control bypass anywhere in the contracts.
- `withdrawFees` reads `feeCollector` fresh each call (no stale-collector bug).
- Gate modifier logic was correct as written (only coverage was missing).
- Grant validity-window inequalities are correct (valid at exact bounds).
- `policy_check`'s canonical `allowed` boolean was never wrong (single atomic
  read); only the cosmetic reasons could race (now fixed).

## Deployment note

Only `GrantVerifier` and `PolicyGate` changed this round; `PolicyRegistry` is
byte-identical to the live Sepolia deployment. **Sepolia is now fully current**
(2026-06-12): the new `GrantVerifier` (8-field target-bound grant) is deployed
at `0x3510B9427BeadD04D052E0b01248a6A6A1f23dc9`, Etherscan-verified, pointing at
the unchanged registry `0x5D127b04…`. A live round-trip confirmed a just-issued
grant verifies immediately on Sepolia.

## Bonus fix found during Sepolia verification

The live test surfaced the documented clock-skew footgun in practice: a grant
signed with `issuedAt = wall-clock now` transiently fails `isGrantValid` because
Sepolia's latest `block.timestamp` lags real time by up to a block (~12s). Fixed
at the source — the MCP issuer now backdates `issuedAt` by a 60s buffer, so
just-issued grants are immediately valid on lagging chains without changing the
forward-looking expiry. (`mcp/src/grants.ts`; guide note updated.)
