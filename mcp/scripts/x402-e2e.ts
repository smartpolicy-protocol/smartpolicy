/**
 * End-to-end x402 payment test against the LIVE hosted API.
 * Proves: 402 challenge → signed USDC payment → facilitator settle → tool
 * result + on-chain balance change.
 *
 * Env: X402_TEST_KEY — private key of a wallet holding Base Sepolia USDC.
 * Run: X402_TEST_KEY=0x... npx tsx scripts/x402-e2e.ts
 */
import assert from "node:assert/strict";
import { createPublicClient, http, erc20Abi, type Address, type Hex } from "viem";
import { baseSepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { wrapFetchWithPayment, decodeXPaymentResponse } from "x402-fetch";

const API = process.env.SMARTPOLICY_API ?? "https://api.smartpolicy.io/mcp";
const USDC: Address = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const PAY_TO: Address = "0xaC7B68fd202717Bc57996c6FA7c1DB39264b4Aee";

const key = process.env.X402_TEST_KEY as Hex | undefined;
if (!key) throw new Error("X402_TEST_KEY required");
const account = privateKeyToAccount(key);
const chain = createPublicClient({ chain: baseSepolia, transport: http("https://sepolia.base.org") });

const usdcBalance = (addr: Address) =>
  chain.readContract({ address: USDC, abi: erc20Abi, functionName: "balanceOf", args: [addr] });

const payerBefore = await usdcBalance(account.address);
const payeeBefore = await usdcBalance(PAY_TO);
console.log(`payer ${account.address}: ${payerBefore} µUSDC | payee: ${payeeBefore} µUSDC`);
assert.ok(payerBefore > 0n, "payer has no USDC — fund via faucet.circle.com (Base Sepolia)");

const body = {
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: {
    name: "policy_create",
    arguments: { metadataURI: "ipfs://x402-e2e-test", openMembership: false },
  },
};
const headers = { "content-type": "application/json", accept: "application/json, text/event-stream" };

// 1. Unpaid call must be refused with a 402 challenge.
const unpaid = await fetch(API, { method: "POST", headers, body: JSON.stringify(body) });
assert.equal(unpaid.status, 402, `expected 402 unpaid, got ${unpaid.status}`);
console.log("unpaid call -> 402 challenge OK");

// 2. Paid call via x402-fetch (signs EIP-3009 transferWithAuthorization, retries).
const fetchWithPay = wrapFetchWithPayment(fetch, account);
const paid = await fetchWithPay(API, { method: "POST", headers, body: JSON.stringify(body) });
const text = await paid.text();
assert.equal(paid.status, 200, `expected 200 paid, got ${paid.status}: ${text}`);

const settle = decodeXPaymentResponse(paid.headers.get("x-payment-response")!);
console.log("settle response:", JSON.stringify(settle));
assert.match(text, /createPolicy/, "tool result missing unsigned tx");
console.log("paid tools/call -> 200, tool result received");

// 3. On-chain proof: 1000 µUSDC ($0.001) moved payer -> payee.
let payerAfter = payerBefore, payeeAfter = payeeBefore;
for (let i = 0; i < 12 && payeeAfter === payeeBefore; i++) {
  await new Promise((r) => setTimeout(r, 5000));
  [payerAfter, payeeAfter] = await Promise.all([usdcBalance(account.address), usdcBalance(PAY_TO)]);
}
console.log(`payer ${payerAfter} (${payerAfter - payerBefore}) | payee ${payeeAfter} (+${payeeAfter - payeeBefore})`);
assert.equal(payeeAfter - payeeBefore, 1000n, "payee did not receive 1000 µUSDC");
console.log("X402 E2E OK — $0.001 USDC settled on Base Sepolia");
