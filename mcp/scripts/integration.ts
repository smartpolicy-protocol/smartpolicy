/**
 * End-to-end integration proof against a local anvil chain.
 *
 * Prereqs (see PLAN.md "How to resume work"):
 *   1. anvil running on 127.0.0.1:8545
 *   2. contracts deployed:  forge script script/Deploy.s.sol --broadcast \
 *        --rpc-url http://127.0.0.1:8545 --private-key <anvil key 0>
 *   3. env: SMARTPOLICY_REGISTRY, SMARTPOLICY_VERIFIER set to the deployed
 *      addresses; SMARTPOLICY_ISSUER_KEY set (anvil key 1 works)
 *
 * Exercises the exact code paths the MCP tools use:
 *   create policy -> add member + issuer -> policy_check -> grant_issue ->
 *   verify grant on-chain -> consume -> replay must fail -> revoke member ->
 *   policy_check flips to deny.
 */
import { createWalletClient, decodeEventLog, http, publicActions, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { registryAbi, verifierAbi } from "../src/abi.js";
import { loadConfig } from "../src/config.js";
import { GrantIssuer } from "../src/grants.js";
import { Registry } from "../src/registry.js";

const ANVIL_KEY_0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex; // owner
const AGENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" as const; // anvil account 1

let failures = 0;
function expect(label: string, actual: unknown, wanted: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(wanted);
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}${ok ? "" : ` (got ${JSON.stringify(actual)}, wanted ${JSON.stringify(wanted)})`}`);
  if (!ok) failures++;
}

const config = loadConfig();
const registry = new Registry(config);
const issuer = new GrantIssuer(config);
const owner = createWalletClient({
  account: privateKeyToAccount(ANVIL_KEY_0),
  transport: http(config.rpcUrl),
}).extend(publicActions);
const chain = null; // anvil; viem infers from rpc

async function send(tx: { to: `0x${string}`; value: string; data: Hex }) {
  const hash = await owner.sendTransaction({ to: tx.to, value: BigInt(tx.value), data: tx.data, chain });
  return owner.waitForTransactionReceipt({ hash });
}

// 1. create a policy through the same builder policy_create uses
const receipt = await send(await registry.buildCreatePolicy({ metadataURI: "ipfs://integration-test" }));
const created = receipt.logs
  .map((log) => {
    try {
      return decodeEventLog({ abi: registryAbi, data: log.data, topics: log.topics });
    } catch {
      return undefined;
    }
  })
  .find((event) => event?.eventName === "PolicyCreated");
const policyId = (created?.args as { policyId: bigint }).policyId;
console.log(`created policy ${policyId}`);

// 2. add the agent as member, authorize the server's issuer key
await send(await registry.buildUpdate(policyId, { kind: "addMembers", members: [AGENT] }));
await send(await registry.buildUpdate(policyId, { kind: "addIssuer", issuer: issuer.address }));

// 3. policy_check: member allowed, stranger denied
expect("member is allowed", (await registry.check(policyId, AGENT, "withdraw")).allowed, true);
expect("stranger is denied", (await registry.check(policyId, owner.account.address, "withdraw")).allowed, false);

// 4. action rules change the answer without touching any contract
await send(await registry.buildUpdate(policyId, { kind: "setActionRule", action: "withdraw", rule: "NOBODY" }));
expect("NOBODY rule denies the member", (await registry.check(policyId, AGENT, "withdraw")).allowed, false);
expect("other actions unaffected", (await registry.check(policyId, AGENT, "report")).allowed, true);
await send(await registry.buildUpdate(policyId, { kind: "setActionRule", action: "withdraw", rule: "UNSET" }));

// 5. grant_issue -> on-chain isGrantValid must accept (EIP-712 domain match).
//    target = owner (the EOA that will call consumeGrant directly here).
const issued = await issuer.issue(policyId, AGENT, "sweep", 600, owner.account.address);
const grantTuple = {
  policyId: BigInt(issued.grant.policyId),
  subject: issued.grant.subject,
  action: issued.grant.action,
  issuedAt: BigInt(issued.grant.issuedAt),
  expiresAt: BigInt(issued.grant.expiresAt),
  nonce: BigInt(issued.grant.nonce),
  issuer: issued.grant.issuer,
  target: issued.grant.target,
  context: issued.grant.context,
};
const valid = await owner.readContract({
  address: config.verifier,
  abi: verifierAbi,
  functionName: "isGrantValid",
  args: [grantTuple, issued.signature],
});
expect("issued grant verifies on-chain", valid, true);

// 6. consume on-chain, then replay must be invalid
const consumeHash = await owner.writeContract({
  address: config.verifier,
  abi: verifierAbi,
  functionName: "consumeGrant",
  args: [grantTuple, issued.signature],
  chain,
});
await owner.waitForTransactionReceipt({ hash: consumeHash });
const replay = await owner.readContract({
  address: config.verifier,
  abi: verifierAbi,
  functionName: "isGrantValid",
  args: [grantTuple, issued.signature],
});
expect("consumed grant cannot be replayed", replay, false);

// 7. revocation is instant
await send(await registry.buildUpdate(policyId, { kind: "removeMembers", members: [AGENT] }));
expect("removed member is denied", (await registry.check(policyId, AGENT, "withdraw")).allowed, false);

console.log(failures === 0 ? "\nINTEGRATION OK" : `\nINTEGRATION FAILED (${failures})`);
process.exit(failures === 0 ? 0 : 1);
