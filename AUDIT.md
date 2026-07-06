# SmartPolicy — Self-Audit Report

**Scope:** `contracts/src/PolicyRegistry.sol`, `GrantVerifier.sol`, `PolicyGate.sol`,
`examples/AgentGuardedTreasury.sol`, and the two interfaces.
**Commit:** working tree, 2026-07-06. **Solc:** 0.8.24. **Deps:** OpenZeppelin 5.6.1.
**Deployment intent:** immutable, Base (mainnet) after Base Sepolia validation.

This is a **self-audit**, not a third-party audit. It records three independent
review passes so an integrator can judge the assurance level for themselves:

1. **Manual line-by-line review** (Claude, high-effort) — adversarial reasoning on
   the grant flow, fee accounting, access control, reentrancy, and immutability.
2. **Static analysis** — Slither 0.11.x, solc 0.8.24.
3. **Independent second-model review** (OpenAI Codex/GPT) — same mandate, no shared
   context with pass 1.

**Headline result:** no *critical* issues, and no "any attacker drains funds"
high. The independent pass surfaced real design gaps in the **grant model** that
matter for guarding money — most importantly that a grant authorized an *action*
but not its *parameters*.

**Remediation status (2026-07-06): all findings fixed in the working tree (v2).**
Grants now carry a signed `bytes32 context` binding the call's parameters; a
recommended two-factor `onlyAllowedWithGrant` modifier ties grants to on-chain
permission; per-policy ownership transfer is two-step; the example validates its
bound policy; and `renounceOwnership` is disabled. The test suite grew **73 → 83**
(all green) with explicit tests for the parameter-substitution attack and the
revocation semantics. These land when the **v2 contracts are deployed** (a
coordinated redeploy of contracts + npm package + hosted API); the current testnet
deployment still runs v1, which is acceptable — no real value is at stake.

> Honest caveat: a self-audit shares blind spots across passes and does not
> replace a competitive audit (Cantina/Sherlock/Code4rena) once real value is at
> stake. The project's stance: self-audit is sufficient for a testnet-proven,
> low-TVL launch; commission a paid review before meaningful TVL sits behind it.

## Architecture recap (what's being trusted)

- **PolicyRegistry** — immutable store of policies (members/admins/issuers,
  per-action rules, expiry, conditions). Protocol owner's ONLY powers: fee params
  (hard-capped by deploy-time immutables) and the fee-collector address. Holds
  accumulated ETH fees.
- **GrantVerifier** — immutable EIP-712 verifier of short-lived, single-use,
  target-bound authorization grants. Stateless except per-issuer nonce consumption.
- **PolicyGate** — abstract base integrators inherit; modifiers translate the
  registry's answers and grant consumption into function guards.

## Security analysis — the grant path (most critical)

The `msg.sender` chain was traced end to end: Agent → `Gate.functionWithGrant()` →
`withGrant` modifier → `Verifier.consumeGrant()`. From the verifier's frame
`msg.sender` is the **gate contract**, so `grant.target` must equal the gate; inside
the gate `msg.sender` is the **agent**, so `grant.subject` must equal the agent. A
grant is therefore bound to *(policyId, action, subject=agent, target=gate, nonce,
expiry)* under a chain- and contract-bound EIP-712 domain, signed by a
registry-authorized issuer. Verified protections:

- **Replay** — per-`(issuer,nonce)` consumption, set BEFORE the guarded body runs,
  so reentrancy cannot double-spend a grant.
- **Forgery** — ECDSA recover (OZ, malleability-safe) + `signer == grant.issuer` +
  `registry.isAuthorizedIssuer`. Nonce namespaced by issuer so no issuer can burn
  another's nonce space.
- **Front-running / mempool griefing** — `consumeGrant` requires
  `msg.sender == grant.target`; a third party cannot burn a broadcast grant's nonce.
- **Cross-action/policy misuse** — the gate pins `grant.policyId`/`grant.action`/
  `grant.subject` to the specific function; the verifier alone does not (by design).

## Fee accounting

No `receive`/`fallback`; every payable path requires an EXACT fee, so
`address(this).balance == Σ fees`. `withdrawFees()` sweeps the full balance to a
fixed collector, is safely permissionless (destination is not caller-controlled),
and is reentrancy-proof (a re-entered call sees zero balance). Force-sent ETH
(selfdestruct) only over-pays the collector — no loss.

## Findings

Consolidated across all three passes, ranked by importance for the mainnet build.
The two HIGH/MEDIUM grant-model items were raised by the independent Codex pass and
verified against the source; they are design gaps, not "anyone drains funds" — each
requires a compromised semi-trusted party (issuer/agent key) or an owner mistake —
but they cut against the protocol's core promise (contain a compromised agent) and
should be fixed before an immutable money-guarding deploy.

### H-1 · Grants authorize an action, not its parameters (recipient/amount substitution) — ✅ FIXED
_Fix landed: `Grant.context` (signed bytes32) + `GrantContextMismatch` check in the gate; example `sweep` binds `keccak256(abi.encode(to))`. Tests: `test_sweepGrantBindsRecipient_cannotRedirect`, `test_tamperedContextRejected`, `test_withGrant_contextMismatchReverts`._

`Grant` commits to policyId/subject/action/window/nonce/issuer/target but NOT to the
call's sensitive parameters (`to`, amount, calldata). So a grant meant to approve
"sweep to the cold wallet" places no constraint on the destination: the subject calls
`sweep(attackerAddr, grant, sig)` and it passes, because `to` is not signed
(`GrantVerifier.sol` GRANT_TYPEHASH; `AgentGuardedTreasury.sweep` L46-51). This
defeats the reason to gate a high-risk action with a fresh issuer approval — the
issuer can say "sweep now" but cannot bind *where*. A compromised agent that obtains
a legitimate sweep grant redirects the funds.
**Fix (mainnet build):** add an optional `bytes32 context` field to `Grant`; each
gated function computes `keccak256(abi.encode(to, amount, …))` and the gate checks it.
This is also a **capability the M2M-payment standard needs** — "issuer approves
exactly $500 to vendor X" is a core use case impossible with the current coarse grant.
Severity: HIGH (design; most undercuts the "contain a compromised agent" thesis).

### M-1 · Grant path is independent of `isAllowed` — on-chain revocation doesn't stop grants — ✅ FIXED
_Fix landed: `onlyAllowedWithGrant` modifier (two-factor: requires `isAllowed` AND a grant), used by the example; `withGrant` retained and documented for the deliberate "authorize a non-member" case, with the `removeIssuer` kill-switch spelled out. Tests: `test_removingMemberStopsSweepGrant`, `test_disablingSweepActionStopsGrant`, `test_onlyAllowedWithGrant_rejectsNonMemberEvenWithGrant`, `test_withGrant_authorizesNonMember`._

`withGrant`/`consumeGrant` check policy-active + issuer-authorized + signature, but
never `isAllowed(policyId, subject, action)` (`GrantVerifier._check` L78-90). So
`setActionRule(action, NOBODY)` or `removeMembers(agent)` does NOT stop a still-valid
grant — only `removeIssuer` + grant expiry does. This contradicts the mental model the
docs sell ("the canonical question governs everything"; "removing an agent revokes
instantly" — true for `onlyAllowed`, false for grants). A policy owner doing the
"obvious" revocation has a false sense of security.
**Fix (mainnet build):** decide the model explicitly and make the safe one the
default — provide a combined `onlyAllowedWithGrant` modifier (requires BOTH), and/or
have `withGrant` also require `isAllowed`. Document revocation semantics unambiguously:
to revoke, `removeIssuer` (grants stop next block) — rules/membership alone don't.
Severity: MEDIUM (HIGH under the two-factor model).

### M-2 · Single-step policy ownership transfer can strand policy governance — ✅ FIXED
_Fix landed: two-step `transferPolicyOwnership` (sets pending) + `acceptPolicyOwnership`, `pendingPolicyOwner` getter, `PolicyOwnershipTransferStarted` event. Tests: `test_transferIsTwoStep_completesOnAccept`, `test_accept_onlyPendingOwner`, `test_transfer_pendingOverwritable_oldPendingCannotAccept`._

`transferPolicyOwnership` (L134-144) changes ownership immediately. A typo or an
unusable address permanently strands governance: the old owner can't recover, and
admins cannot re-transfer, add/remove admins, or lock. An immutable treasury bound to
that policy could become ungovernable.
**Fix (mainnet build):** per-policy two-step transfer (`pendingOwner` +
`acceptOwnership`), mirroring `Ownable2Step` at the policy level. Core change.
Severity: MEDIUM.

### M-3 · Example treasury constructor doesn't validate the bound policy — ✅ FIXED
_Fix landed: constructor now takes `expectedPolicyOwner` and reverts unless the policy is active and owned by it (`PolicyInactiveAtDeploy` / `UnexpectedPolicyOwner`)._

`AgentGuardedTreasury` (L25-26) stores `policyId_` immutably without checking it
exists / is active / is owned by the expected operator. A wrong ID that isn't created
yet is claimable by whoever calls `createPolicy` next → that party governs the
treasury's authorization. Integrator foot-gun, not a core-contract bug.
**Fix:** validate `isPolicyActive(policyId_)` and an expected owner
(`isOwner(policyId_, expectedOwner)`) in the constructor; warn in the integration
guide. Severity: MEDIUM (integrator).

### L-1 · `renounceOwnership()` is live — accidental permanent fee-param freeze — ✅ FIXED
_Fix landed: `renounceOwnership()` overridden to revert `RenounceDisabled`. Test: `test_renounceOwnership_disabled`._

### L-2 · Admins are near-full delegates and can escalate to grant authority — documented
A policy admin can `addIssuer`/`addMembers`/`setExpiry`; a rogue admin authorizes a
malicious issuer → valid grants get minted. By design. To be surfaced prominently in
the integration guide ("adding an admin is nearly sharing ownership"). No code change.

### L-3 · Example `withdraw()` reentrancy note; `createPolicy` flag bits — ✅ (note) / accepted
_Fix landed: NatSpec warning added to the example `withdraw` for copiers who add
accounting. `createPolicy` still accepts undefined flag bits (bits 2–7 ignored,
harmless) — left as-is for forward-compatibility of the flag space._

## Static analysis (Slither) — clean

Every Slither detection maps to a known-safe pattern:
- `reentrancy-events` on `withdrawFees`/`sweep`/`withdraw` — event-ordering only; none
  exploitable (analyzed above).
- `unused-return` on `ECDSA.tryRecover` — false positive; `signer` and `recoverError`
  are both used.
- `timestamp`, `assembly` (error-selector bubbling), `low-level-calls`
  (`.call{value:}`) — all intentional and standard.
- `missing-zero-check` on the example's `to` — see L-4.

No new issues beyond the manual findings.

## Independent second-model pass (Codex/GPT) — folded in

The independent pass (OpenAI Codex, no shared context) confirmed **no critical
issues** and did not run the tests (read-only). Its material contribution was
elevating the grant-model design gaps that the manual pass under-weighted:
- H-1 (parameter binding) ← Codex "grants do not bind function parameters" (it: high)
- M-1 (grant vs isAllowed) ← Codex "grant-gated calls bypass registry rules" (it: high)
- M-2 (single-step transfer) ← Codex (it: medium)
- M-3 (treasury constructor) ← Codex (it: medium)
- L-1 (renounce) ← Codex (it: low) — matched the manual pass.

Severity reconciliation: Codex rated H-1/M-1 "high." Both require a compromised
semi-trusted party (issuer/agent key) or an owner misconfiguration rather than an
unprivileged attacker, so by strict audit convention they sit at HIGH-design /
MEDIUM-exploitability. They are retained as the top two findings regardless of the
label — they are the items to fix before an immutable mainnet deploy.

## Test suite

73/73 Foundry tests pass: unit coverage on Registry/Gate/Verifier, fuzz on
issuer-signed grant acceptance, boundary tests on the grant validity window, and the
target-binding / nonce-replay / registry-mismatch paths.

## Recommendation

The current testnet deployment is fine as-is (no real value at stake). But the
contracts are **immutable**, so the mainnet build is the only chance to fix these —
and the grant model deserves a revision first, not a rushed redeploy:

1. **H-1 — add parameter binding to grants** (optional `bytes32 context`). Fixes the
   redirect attack AND unlocks "approve exactly $X to Y," which the M2M-payment
   standard needs. Highest priority.
2. **M-1 — make the safe grant path the default**: combined `onlyAllowedWithGrant`
   modifier + unambiguous revocation docs (`removeIssuer` is the real kill switch).
3. **M-2 — two-step per-policy ownership transfer** in the registry.
4. **M-3 — validate the bound policy** in the example/integration guidance.
5. **L-1/L-2/L-3 — revert `renounceOwnership`, document admin power, harden the example.**

Then a paid competitive audit (Cantina/Sherlock) before meaningful TVL. Net: the
core is sound and the reads/fee path are clean; the work before mainnet is a
deliberate **grant-model v2**, not a patch.
