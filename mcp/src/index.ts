#!/usr/bin/env node
/**
 * SmartPolicy MCP server.
 *
 *   smartpolicy-mcp          — stdio transport (local MCP clients)
 *   smartpolicy-mcp serve    — Streamable HTTP transport + optional x402 metering
 *   smartpolicy-mcp deploy   — bootstrap Registry+Verifier on any chain
 *
 * Free reads:  policy_check, policy_get, policy_fees, grant_verify, grant_issuer_info
 * Issuance:    grant_issue (requires SMARTPOLICY_ISSUER_KEY)
 * Writes:      policy_create, policy_update — return unsigned calldata for the
 *              caller's own wallet; this server never holds user keys.
 */
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./config.js";
import { deploy } from "./deploy.js";
import { GrantIssuer } from "./grants.js";
import { serve } from "./http.js";
import { Registry } from "./registry.js";
import { buildServer } from "./server.js";

// NOTE: no process.exit() anywhere in this package — on Windows it races
// libuv's handle teardown (UV_HANDLE_CLOSING assertion, exit 0xC0000409)
// while viem's keep-alive sockets are open. Let the event loop drain instead.
async function startStdio(): Promise<void> {
  const config = loadConfig();
  const registry = new Registry(config);
  const issuer = config.issuerKey ? new GrantIssuer(config) : undefined;

  // Best-effort chainId reconciliation at startup (M2): warn loudly if the
  // configured chainId disagrees with the RPC, since grants would silently fail.
  // Non-fatal — free reads still work even if the RPC is briefly unreachable.
  try {
    await registry.assertChainId();
  } catch (error) {
    console.error(`WARNING: ${error instanceof Error ? error.message : String(error)}`);
  }

  const server = buildServer(config, registry, issuer);
  await server.connect(new StdioServerTransport());
}

if (process.argv[2] === "deploy") {
  await deploy();
} else if (process.argv[2] === "serve") {
  await serve();
} else {
  await startStdio();
}
