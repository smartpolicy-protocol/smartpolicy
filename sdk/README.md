# @smartpolicy/sdk

TypeScript SDK for **SmartPolicy** — runtime authorization for AI agents and
smart contracts. Check on-chain policies, issue EIP-712 grants, and build policy
transactions, in a few calls. Wraps [viem]; never holds your keys.

```bash
npm install @smartpolicy/sdk
```

## The one question

Everything reduces to: *may this subject do this action under this policy?*

```ts
import { SmartPolicy } from "@smartpolicy/sdk";

const sp = SmartPolicy.baseSepolia();            // zero-config against the testnet
const ok = await sp.isAllowed(1n, "0xAgent…", "withdraw");   // → boolean

const why = await sp.check(1n, "0xAgent…", "withdraw");
// { allowed, exists, active, rule: "MEMBERS", isMember, reasons: [...] }
```

A protected contract answers the *identical* question on-chain via `PolicyGate`,
so your backend and your contract never disagree.

## Protect your agent's treasury in 5 minutes

**1. Deploy your gated contract.** Inherit `PolicyGate` and gate the sensitive
functions (see `contracts/src/examples/AgentGuardedTreasury.sol`). For money
movement, use the two-factor `onlyAllowedWithGrant` and bind the parameters:

```solidity
function sweep(address payable to, IGrantVerifier.Grant calldata g, bytes calldata sig)
    external
    onlyAllowedWithGrant(policyId, ACTION_SWEEP, keccak256(abi.encode(to)), g, sig)
{ /* … */ }
```

**2. Create a policy and add your agent** — build the txs, sign with your wallet:

```ts
const create = await sp.buildCreatePolicy({ openMembership: false }); // {to,value,data}
// … submit `create` from the wallet that should OWN the policy; read the
//    new policyId from the PolicyCreated event …
const add = await sp.buildAddMembers(policyId, ["0xAgent…"]);         // {to,value,data}
```

**3. Run your own issuer** (the "your issuers, not ours" model). Authorize its
address on the policy (`buildAddIssuer`), then mint short-lived grants after
whatever off-chain checks you want — budgets, KYC, rate limits:

```ts
import { GrantIssuer, bindContext } from "@smartpolicy/sdk";

const issuer = new GrantIssuer(sp, process.env.ISSUER_KEY);  // your key, your rules
console.log("authorize this issuer on the policy:", issuer.address);

const { grant, signature, tuple } = await issuer.issue({
  policyId,
  subject: "0xAgent…",
  action: "sweep",
  target: treasuryAddress,               // only this contract may redeem it
  ttlSeconds: 600,                        // short-lived
  context: bindContext(["address"], [coldWallet]),  // ← binds the destination
});

await sp.verifyGrant(grant, signature);  // pre-flight before broadcasting
// pass (grant, signature) to treasury.sweep(coldWallet, grant, signature)
```

Because the grant's `context` is the signed `keccak256(abi.encode(coldWallet))`,
a compromised agent **cannot** redirect the sweep — any other `to` reverts. The
issuer approved "sweep to the cold wallet," not "sweep."

## Revocation

- **Membership / rules:** `buildRemoveMembers` or `buildSetActionRule(…, "NOBODY")`
  — stops the on-chain path immediately, and (with `onlyAllowedWithGrant`) grants too.
- **Issuer:** `buildRemoveIssuer` — the kill-switch for the grant path; outstanding
  grants stop verifying the next block.

## API

- `SmartPolicy.baseSepolia()` / `new SmartPolicy({ rpcUrl, chainId, registry, verifier })`
- Reads: `isAllowed` · `check` · `getPolicy` · `isMember` · `isAdmin` · `isOwner`
  · `isAuthorizedIssuer` · `fees` · `assertChainId`
- Grants: `GrantIssuer#issue` · `verifyGrant` · `bindContext` · `actionId`
- Build (unsigned `{to,value,data}` for the caller's wallet): `buildCreatePolicy`
  · `buildAddMembers` · `buildRemoveMembers` · `buildSetActionRule` · `buildAddIssuer`
  · `buildRemoveIssuer` · `buildAddAdmin` · `buildSetExpiry`
- Constants: `BASE_SEPOLIA` · `DEPLOYMENTS` · `registryAbi` · `verifierAbi`

## Notes

- **Base Sepolia is the canonical testnet.** Mainnet is not deployed yet
  (pending audit — see the repo's `AUDIT.md`). Point at your own deployment with
  the `SmartPolicy` constructor.
- Grants are **v2** (9-field, with `context`). This SDK and the on-chain
  `GrantVerifier` must match — they do, out of the box.
- Apache-2.0. Repo: <https://github.com/smartpolicy-protocol/smartpolicy>.

[viem]: https://viem.sh
