/**
 * Smoke test for `smartpolicy-mcp serve`: free reads work over Streamable
 * HTTP, paid tools 402 without payment when x402 is enabled.
 * Assumes a server on SMARTPOLICY_PORT (default 3402) started with
 * SMARTPOLICY_X402_PAY_TO set. Run: npm run smoke:http
 */
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const port = process.env.SMARTPOLICY_PORT ?? "3402";
const base = `http://localhost:${port}`;

// 1. health
const health = await (await fetch(`${base}/healthz`)).json();
assert.equal(health.ok, true, "healthz not ok");
console.log("healthz:", JSON.stringify(health));

// 2. MCP handshake + free read over Streamable HTTP
const client = new Client({ name: "smoke", version: "0.0.0" });
await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`)));
const tools = await client.listTools();
assert.ok(tools.tools.length >= 8, `expected >=8 tools, got ${tools.tools.length}`);
const fees = await client.callTool({ name: "policy_fees", arguments: {} });
const feesText = (fees.content as Array<{ text: string }>)[0].text;
assert.match(feesText, /creationFeeWei/, "policy_fees did not return fees");
console.log("policy_fees (free, no payment):", feesText.replaceAll("\n", " "));

// 3. paid tool without X-PAYMENT → HTTP 402 with x402 accepts[]
const res = await fetch(`${base}/mcp`, {
  method: "POST",
  headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
  body: JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name: "grant_issue", arguments: {} },
  }),
});
assert.equal(res.status, 402, `expected 402 for unpaid grant_issue, got ${res.status}`);
const challenge = await res.json();
assert.equal(challenge.x402Version, 1);
assert.equal(challenge.accepts?.[0]?.scheme, "exact");
assert.ok(challenge.accepts?.[0]?.payTo, "402 challenge missing payTo");
console.log("grant_issue without payment → 402, challenge:", JSON.stringify(challenge.accepts[0]));

await client.close();
console.log("SMOKE OK");
