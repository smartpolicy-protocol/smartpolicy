/**
 * `smartpolicy-mcp serve` — Streamable HTTP transport with optional x402
 * metering. Stateless: each POST /mcp gets a fresh McpServer + transport
 * (Registry/GrantIssuer are shared; grant nonces are random, no state).
 *
 * Payments (x402, https://x402.org): enabled by setting
 *   SMARTPOLICY_X402_PAY_TO      — USDC receiving address (enables metering)
 *   SMARTPOLICY_X402_PRICE_USDC  — price per paid call in USDC (default 0.001)
 *   SMARTPOLICY_X402_FACILITATOR — default https://x402.org/facilitator
 *                                  (keyless, testnet; use CDP for mainnet)
 *   SMARTPOLICY_PUBLIC_URL       — public base URL for the `resource` field
 *   SMARTPOLICY_PORT             — default 3402
 * Without PAY_TO every tool is free (the self-host default). Only
 * grant_issue / policy_create / policy_update are ever metered; reads stay
 * free per ARCHITECTURE.md §4.
 *
 * ponytail: payment is settled BEFORE the tool runs — a tool-level error can
 * consume a payment. Acceptable at $0.001/call; refund-on-error needs an
 * escrow pattern, add if anyone actually complains.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { loadConfig, type Config } from "./config.js";
import { GrantIssuer } from "./grants.js";
import { Registry } from "./registry.js";
import { buildServer } from "./server.js";

const PAID_TOOLS = new Set(["grant_issue", "policy_create", "policy_update"]);

/** x402 `exact` scheme needs the chain's USDC contract + network slug. */
const X402_NETWORKS: Record<number, { network: string; usdc: string }> = {
  84532: { network: "base-sepolia", usdc: "0x036CbD53842c5426634e7929541eC2318f3dCF7e" },
  8453: { network: "base", usdc: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" },
};

interface X402Config {
  payTo: string;
  priceAtomic: string; // USDC has 6 decimals
  facilitator: string;
  network: string;
  usdc: string;
  publicUrl: string;
}

function loadX402(config: Config, port: number): X402Config | undefined {
  const payTo = process.env.SMARTPOLICY_X402_PAY_TO;
  if (!payTo) return undefined;
  const net = X402_NETWORKS[config.chainId];
  if (!net) {
    console.error(`WARNING: x402 metering not supported on chainId ${config.chainId}; running free.`);
    return undefined;
  }
  const priceUsdc = Number(process.env.SMARTPOLICY_X402_PRICE_USDC ?? "0.001");
  if (!Number.isFinite(priceUsdc) || priceUsdc <= 0) {
    throw new Error(`invalid SMARTPOLICY_X402_PRICE_USDC: ${process.env.SMARTPOLICY_X402_PRICE_USDC}`);
  }
  return {
    payTo,
    priceAtomic: String(Math.round(priceUsdc * 1_000_000)),
    facilitator: process.env.SMARTPOLICY_X402_FACILITATOR ?? "https://x402.org/facilitator",
    network: net.network,
    usdc: net.usdc,
    publicUrl: process.env.SMARTPOLICY_PUBLIC_URL ?? `http://localhost:${port}`,
  };
}

function paymentRequirements(x: X402Config, toolName: string) {
  return {
    scheme: "exact",
    network: x.network,
    maxAmountRequired: x.priceAtomic,
    resource: `${x.publicUrl}/mcp#${toolName}`,
    description: `SmartPolicy MCP tool: ${toolName}`,
    mimeType: "application/json",
    payTo: x.payTo,
    maxTimeoutSeconds: 60,
    asset: x.usdc,
    extra: { name: "USDC", version: "2" }, // EIP-712 domain of USDC transferWithAuthorization
  };
}

async function facilitatorPost(x: X402Config, path: string, paymentHeader: string, requirements: unknown) {
  let paymentPayload: unknown;
  try {
    paymentPayload = JSON.parse(Buffer.from(paymentHeader, "base64").toString("utf8"));
  } catch {
    return { ok: false, reason: "malformed X-PAYMENT header (expected base64 JSON)" };
  }
  const res = await fetch(`${x.facilitator}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ x402Version: 1, paymentPayload, paymentRequirements: requirements }),
  });
  if (!res.ok) return { ok: false, reason: `facilitator ${path} returned HTTP ${res.status}` };
  return { ok: true, body: (await res.json()) as Record<string, unknown> };
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

function send402(res: ServerResponse, x: X402Config, toolName: string, error: string): void {
  sendJson(res, 402, { x402Version: 1, error, accepts: [paymentRequirements(x, toolName)] });
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

export async function serve(): Promise<void> {
  const config = loadConfig();
  const registry = new Registry(config);
  const issuer = config.issuerKey ? new GrantIssuer(config) : undefined;
  const port = Number(process.env.SMARTPOLICY_PORT ?? 3402);
  const x402 = loadX402(config, port);

  try {
    await registry.assertChainId();
  } catch (error) {
    console.error(`WARNING: ${error instanceof Error ? error.message : String(error)}`);
  }

  const httpServer = createServer(async (req, res) => {
    // CORS: the API is public and stateless; browsers may call it directly.
    res.setHeader("access-control-allow-origin", "*");
    res.setHeader("access-control-allow-headers", "content-type, accept, x-payment, mcp-session-id, mcp-protocol-version");
    res.setHeader("access-control-expose-headers", "x-payment-response");
    if (req.method === "OPTIONS") {
      res.writeHead(204).end();
      return;
    }
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);

    if (req.method === "GET" && url.pathname === "/healthz") {
      sendJson(res, 200, {
        ok: true,
        chainId: config.chainId,
        registry: config.registry,
        verifier: config.verifier,
        issuerEnabled: Boolean(issuer),
        x402: x402 ? { network: x402.network, priceAtomicUsdc: x402.priceAtomic, paidTools: [...PAID_TOOLS] } : null,
      });
      return;
    }

    if (url.pathname !== "/mcp") {
      sendJson(res, 404, { error: "not found; MCP endpoint is POST /mcp" });
      return;
    }
    if (req.method !== "POST") {
      // Stateless mode: no SSE stream, no sessions to delete.
      sendJson(res, 405, { error: "stateless server: use POST /mcp" });
      return;
    }

    try {
      const raw = await readBody(req);
      let body: unknown;
      try {
        body = raw ? JSON.parse(raw) : undefined;
      } catch {
        sendJson(res, 400, { error: "invalid JSON body" });
        return;
      }

      // x402 gate: meter tools/call on paid tools only.
      const msg = body as { method?: string; params?: { name?: string } } | undefined;
      const toolName = msg?.method === "tools/call" ? msg.params?.name : undefined;
      if (x402 && toolName && PAID_TOOLS.has(toolName)) {
        const header = req.headers["x-payment"];
        if (typeof header !== "string") {
          send402(res, x402, toolName, "X-PAYMENT header is required for this tool");
          return;
        }
        const requirements = paymentRequirements(x402, toolName);
        const verified = await facilitatorPost(x402, "/verify", header, requirements);
        if (!verified.ok || !(verified.body as { isValid?: boolean } | undefined)?.isValid) {
          const reason =
            (!verified.ok && "reason" in verified && verified.reason) ||
            String((verified.body as Record<string, unknown> | undefined)?.invalidReason ?? "payment invalid");
          send402(res, x402, toolName, reason);
          return;
        }
        const settled = await facilitatorPost(x402, "/settle", header, requirements);
        if (!settled.ok || (settled.body as { success?: boolean } | undefined)?.success === false) {
          const reason =
            (!settled.ok && "reason" in settled && settled.reason) ||
            String((settled.body as Record<string, unknown> | undefined)?.errorReason ?? "settlement failed");
          send402(res, x402, toolName, reason);
          return;
        }
        res.setHeader("x-payment-response", Buffer.from(JSON.stringify(settled.body)).toString("base64"));
      }

      // Fresh server + transport per request (official stateless pattern).
      const server = buildServer(config, registry, issuer);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      res.on("close", () => {
        void transport.close();
        void server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (error) {
      console.error("request failed:", error);
      if (!res.headersSent) {
        sendJson(res, 500, { error: "internal server error" });
      }
    }
  });

  httpServer.listen(port, () => {
    console.error(
      `smartpolicy-mcp listening on :${port} — POST /mcp (chainId ${config.chainId}, ` +
        `issuer ${issuer ? issuer.address : "disabled"}, x402 ${x402 ? `${x402.network} → ${x402.payTo}` : "off (all tools free)"})`,
    );
  });
}
