/**
 * Runnable quickstart. Read-only + off-chain signing against the live Base
 * Sepolia deployment — no funding required. Run: npm run example
 *
 * Shows the full shape without submitting anything on-chain: read a policy,
 * build the txs you'd sign, and mint + pre-flight a parameter-bound grant.
 */
import { SmartPolicy, GrantIssuer, bindContext } from "../src/index.js";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const sp = SmartPolicy.baseSepolia();

// 1. the canonical question
const agent = "0x1111111111111111111111111111111111111111";
const check = await sp.check(1n, agent, "withdraw");
console.log("check policy #1:", check.allowed, "—", check.reasons.join("; "));

// 2. inspect a policy
const policy = await sp.getPolicy(1n);
console.log("policy #1 owner:", policy.owner, "| active:", policy.active);

// 3. build the txs you'd sign with your own wallet (nothing is submitted)
const create = await sp.buildCreatePolicy({ openMembership: false });
console.log("createPolicy tx → to:", create.to, "value:", create.value.toString(), "wei");
const addMember = await sp.buildAddMembers(1n, [agent]);
console.log("addMembers tx → data:", addMember.data.slice(0, 10), "…");

// 4. run an issuer and mint a parameter-bound grant (off-chain signature)
const key = generatePrivateKey();
const issuer = new GrantIssuer(sp, key);
console.log("issuer address (authorize via buildAddIssuer):", issuer.address);

const coldWallet = "0x000000000000000000000000000000000000dEaD";
const { grant, signature } = await issuer.issue({
  policyId: 1n,
  subject: agent,
  action: "sweep",
  target: "0x2222222222222222222222222222222222222222",
  ttlSeconds: 600,
  context: bindContext(["address"], [coldWallet]), // "sweep to THIS address only"
});
console.log("grant issued, action bound to context:", grant.context.slice(0, 12), "…");

// 5. pre-flight against the on-chain verifier (valid:false here — this random
//    issuer isn't authorized on policy #1 — but the call path + tuple are proven)
const pre = await sp.verifyGrant(grant, signature);
console.log("verifyGrant:", pre, "(valid:false expected — issuer not authorized on #1)");

console.log("\nInstall it: npm install @smartpolicy/sdk");
