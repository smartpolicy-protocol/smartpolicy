/**
 * SDK smoke test against the LIVE Base Sepolia v2 deployment. No funding needed
 * (reads + off-chain signing only). Run: npm test
 */
import assert from "node:assert/strict";
import { keccak256, toBytes, encodeAbiParameters, recoverTypedDataAddress } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { SmartPolicy, GrantIssuer, actionId, bindContext, grantTypes, BASE_SEPOLIA } from "../src/index.js";

const sp = SmartPolicy.baseSepolia();

// 1. chainId matches the RPC
await sp.assertChainId();
console.log("assertChainId OK");

// 2. pure helpers
assert.equal(actionId("withdraw"), keccak256(toBytes("withdraw")), "actionId mismatch");
const coldWallet = "0x000000000000000000000000000000000000dEaD";
assert.equal(
  bindContext(["address"], [coldWallet]),
  keccak256(encodeAbiParameters([{ type: "address" }], [coldWallet])),
  "bindContext mismatch",
);
console.log("actionId + bindContext OK");

// 3. live reads — genesis policy #1 exists and has an owner
const p1 = await sp.getPolicy(1n);
assert.equal(p1.exists, true, "genesis policy #1 should exist");
assert.notEqual(p1.owner, `0x${"0".repeat(40)}`, "policy #1 should have an owner");
console.log(`getPolicy(1): owner ${p1.owner}, active ${p1.active}`);

const fees = await sp.fees();
assert.ok(fees.creationFee > 0n, "creationFee should be > 0");
console.log(`fees: create ${fees.creationFee} / update ${fees.updateFee} wei`);

// a random subject is not allowed on a policy with no rules/members
const allowed = await sp.isAllowed(1n, coldWallet, "withdraw");
assert.equal(allowed, false, "random subject should not be allowed");
const checked = await sp.check(1n, coldWallet, "withdraw");
assert.equal(checked.allowed, false);
console.log(`check reasons: ${checked.reasons.join("; ")}`);

// 4. build an unsigned tx (no signing/submitting)
const tx = await sp.buildCreatePolicy({ openMembership: false });
assert.equal(tx.to.toLowerCase(), BASE_SEPOLIA.registry.toLowerCase());
assert.equal(tx.value, fees.creationFee);
assert.match(tx.data, /^0x[0-9a-f]+$/i);
console.log("buildCreatePolicy OK (unsigned tx)");

// 5. grant issuance — signature recovers to the issuer (local EIP-712 verify)
const key = generatePrivateKey();
const issuerAddr = privateKeyToAccount(key).address;
const issuer = new GrantIssuer(sp, key);
assert.equal(issuer.address, issuerAddr);

const issued = await issuer.issue({
  policyId: 1n,
  subject: coldWallet,
  action: "sweep",
  target: "0x1111111111111111111111111111111111111111",
  ttlSeconds: 600,
  context: bindContext(["address"], [coldWallet]),
});
const recovered = await recoverTypedDataAddress({
  domain: { name: "SmartPolicy Grants", version: "1", chainId: sp.chainId, verifyingContract: sp.verifier },
  types: grantTypes,
  primaryType: "Grant",
  message: issued.grant,
  signature: issued.signature,
});
assert.equal(recovered.toLowerCase(), issuerAddr.toLowerCase(), "signature must recover to the issuer");
assert.equal(issued.tuple.split(",").length, 9, "tuple must have 9 fields (v2)");
console.log("grant signed + recovers to issuer OK");

// 6. on-chain verify path works against the live v2 verifier (9-field tuple
//    encodes correctly; unauthorized issuer -> valid:false, not a revert)
const v = await sp.verifyGrant(issued.grant, issued.signature);
assert.equal(v.valid, false, "unauthorized issuer -> not valid");
assert.equal(v.nonceUsed, false, "fresh nonce -> not used");
console.log("verifyGrant on-chain OK (valid:false as expected for an unauthorized issuer)");

console.log("\nSDK SMOKE OK");
