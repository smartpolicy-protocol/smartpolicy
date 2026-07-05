/**
 * SmartPolicy MCP server construction — all tool registrations live here.
 * Transports (stdio in index.ts, Streamable HTTP in http.ts) call buildServer
 * per connection/request; Registry and GrantIssuer are shared singletons
 * (grant nonces are random and stateless, so sharing is safe).
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { isAddress, type Address } from "viem";
import { z } from "zod";
import type { Config } from "./config.js";
import type { GrantIssuer } from "./grants.js";
import type { Registry } from "./registry.js";

const addressSchema = z
  .string()
  .refine(isAddress, "must be a 0x-prefixed Ethereum address")
  .transform((value) => value as Address);

// NOTE: no z.bigint() here — bigint cannot be expressed in JSON Schema and
// silently breaks tools/list serialization in the MCP SDK.
const policyIdSchema = z
  .union([z.string().regex(/^\d+$/), z.number().int().positive()])
  .describe("Policy ID as decimal string or integer");

const toPolicyId = (value: string | number): bigint => BigInt(value);

const actionSchema = z
  .string()
  .min(1)
  .describe('Action name (e.g. "withdraw") or 0x-prefixed bytes32. Names are keccak256-hashed, matching keccak256("withdraw") in the protected contract.');

function json(result: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
}

function jsonError(error: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify({ error: error instanceof Error ? error.message : String(error) }) }],
    isError: true as const,
  };
}

export function buildServer(config: Config, registry: Registry, issuer: GrantIssuer | undefined): McpServer {
  const server = new McpServer(
    { name: "smartpolicy", version: "0.1.0" },
    {
      instructions:
        "SmartPolicy answers one question everywhere: isAllowed(policyId, subject, action). " +
        "Key facts for correct use: (1) ALWAYS read fees first (policy_fees) — write txs need an EXACT msg.value, " +
        "overpaying reverts. (2) Conditions have NO on-chain teeth; only membership, per-action rules, expiry, " +
        "and grants enforce. (3) A grant's subject must be the eventual msg.sender, and only the grant's `target` " +
        "contract may consume it. (4) policy_create/policy_update return UNSIGNED txs for your wallet to sign — " +
        "this server never holds user keys. Verify grants with grant_verify before broadcasting.",
    },
  );

  server.registerTool(
    "policy_check",
    {
      description:
        "THE canonical SmartPolicy question: may `subject` perform `action` under policy `policyId`? " +
        "Returns allowed (boolean) plus the reasons. Maps 1:1 to PolicyRegistry.isAllowed — " +
        "a protected contract gives the identical answer on-chain. Free.",
      inputSchema: {
        policyId: policyIdSchema,
        subject: addressSchema,
        action: actionSchema,
      },
    },
    async ({ policyId, subject, action }) => {
      try {
        return json(await registry.check(toPolicyId(policyId), subject, action));
      } catch (error) {
        return jsonError(error);
      }
    },
  );

  server.registerTool(
    "policy_get",
    {
      description:
        "Read a policy: owner, expiry, active/locked state, membership mode, member count, metadata URI. Free.",
      inputSchema: { policyId: policyIdSchema },
    },
    async ({ policyId }) => {
      try {
        return json(await registry.getPolicy(toPolicyId(policyId)));
      } catch (error) {
        return jsonError(error);
      }
    },
  );

  server.registerTool(
    "grant_issue",
    {
      description:
        "Issue a short-lived single-use EIP-712 grant authorizing `subject` to perform `action` under " +
        "`policyId`, redeemable ONLY at the `target` contract. The subject must pass policy_check first; the " +
        "policy must list this server's issuer address (grant_issuer_info) via addIssuer. Pass the result to " +
        "target's PolicyGate.withGrant function. Verify with grant_verify before broadcasting.",
      inputSchema: {
        policyId: policyIdSchema,
        subject: addressSchema,
        action: actionSchema,
        target: addressSchema.describe("the contract that will consume the grant (the integrator/gate); only it may redeem"),
        ttlSeconds: z
          .number()
          .int()
          .positive()
          .max(86400)
          .default(600)
          .describe("Requested grant lifetime in seconds; clamped to the server's maxGrantTtlSeconds (see grant_issuer_info)"),
      },
    },
    async ({ policyId, subject, action, target, ttlSeconds }) => {
      try {
        if (!issuer) throw new Error("grant issuance disabled on this server (no issuer key configured)");
        await registry.assertChainId();
        const id = toPolicyId(policyId);
        const authorized = await registry.isAuthorizedIssuer(id, issuer.address);
        if (!authorized) {
          throw new Error(
            `this server's issuer address ${issuer.address} is not authorized for policy ${id}; ` +
              "the policy owner must call addIssuer first (see policy_update)",
          );
        }
        const allowed = await registry.check(id, subject, action);
        if (!allowed.allowed) {
          throw new Error(`policy denies this: ${allowed.reasons.join("; ")}`);
        }
        return json(await issuer.issue(id, subject, action, ttlSeconds, target));
      } catch (error) {
        return jsonError(error);
      }
    },
  );

  server.registerTool(
    "grant_issuer_info",
    {
      description: "This server's grant-issuer address (authorize it on a policy via addIssuer) and limits.",
      inputSchema: {},
    },
    async () => {
      return json({
        issuerEnabled: Boolean(issuer),
        issuerAddress: issuer?.address ?? null,
        maxGrantTtlSeconds: config.maxGrantTtl,
        chainId: config.chainId,
        registry: config.registry,
        verifier: config.verifier,
      });
    },
  );

  server.registerTool(
    "policy_fees",
    {
      description:
        "Current protocol fees in wei (read live). createPolicy needs exactly creationFee as msg.value; " +
        "every other write needs exactly updateFee. Read this before building any write tx — wrong value reverts.",
      inputSchema: {},
    },
    async () => {
      try {
        const { creationFee, updateFee } = await registry.fees();
        return json({ creationFeeWei: creationFee.toString(), updateFeeWei: updateFee.toString() });
      } catch (error) {
        return jsonError(error);
      }
    },
  );

  server.registerTool(
    "grant_verify",
    {
      description:
        "Pre-flight a grant before broadcasting: checks the on-chain GrantVerifier for validity (signature, " +
        "validity window, issuer authorization, policy active) and whether the nonce is already used. Returns " +
        "{valid, nonceUsed}. Note: does NOT check subject==caller or target — the gate enforces those on redemption.",
      inputSchema: {
        grant: z
          .object({
            policyId: z.union([z.string(), z.number()]),
            subject: addressSchema,
            action: z.string(),
            issuedAt: z.union([z.string(), z.number()]),
            expiresAt: z.union([z.string(), z.number()]),
            nonce: z.string(),
            issuer: addressSchema,
            target: addressSchema,
          })
          .describe("the grant object exactly as returned by grant_issue"),
        signature: z.string().regex(/^0x[0-9a-fA-F]+$/),
      },
    },
    async ({ grant, signature }) => {
      try {
        return json(
          await registry.verifyGrant(
            { ...grant, action: grant.action as `0x${string}` },
            signature as `0x${string}`,
          ),
        );
      } catch (error) {
        return jsonError(error);
      }
    },
  );

  server.registerTool(
    "policy_create",
    {
      description:
        "Build the unsigned transaction that creates a new policy. Returns {to, value, data} for YOUR " +
        "wallet to sign and submit — the submitting address becomes the policy owner. `value` is the " +
        "protocol creation fee in wei.",
      inputSchema: {
        openMembership: z.boolean().default(false).describe("true: every address counts as a member"),
        transferable: z.boolean().default(false).describe("true: ownership can be transferred later"),
        expiresAt: z.number().int().nonnegative().default(0).describe("unix seconds; 0 = never expires"),
        metadataURI: z
          .string()
          .default("")
          .describe("optional metadata pointer, informational only; prefer ipfs:// (content-immutable)"),
        metadataHash: z
          .string()
          .regex(/^0x[0-9a-fA-F]{64}$/)
          .optional()
          .describe("optional keccak256 of the metadata document — on-chain tamper-evidence for the URI's content"),
      },
    },
    async (opts) => {
      try {
        return json(await registry.buildCreatePolicy({ ...opts, metadataHash: opts.metadataHash as `0x${string}` | undefined }));
      } catch (error) {
        return jsonError(error);
      }
    },
  );

  server.registerTool(
    "policy_update",
    {
      description:
        "Build the unsigned transaction for a policy rule change (submit from the owner or an admin " +
        "wallet; `value` is the protocol update fee in wei). Operations: addMembers, removeMembers, " +
        "setActionRule (UNSET|MEMBERS|ANYONE|NOBODY), addIssuer, removeIssuer, addAdmin, removeAdmin, setExpiry.",
      inputSchema: {
        policyId: policyIdSchema,
        operation: z.discriminatedUnion("kind", [
          z.object({ kind: z.literal("addMembers"), members: z.array(addressSchema).min(1) }),
          z.object({ kind: z.literal("removeMembers"), members: z.array(addressSchema).min(1) }),
          z.object({
            kind: z.literal("setActionRule"),
            action: actionSchema,
            rule: z.enum(["UNSET", "MEMBERS", "ANYONE", "NOBODY"]),
          }),
          z.object({ kind: z.literal("addIssuer"), issuer: addressSchema }),
          z.object({ kind: z.literal("removeIssuer"), issuer: addressSchema }),
          z.object({ kind: z.literal("addAdmin"), admin: addressSchema }),
          z.object({ kind: z.literal("removeAdmin"), admin: addressSchema }),
          z.object({ kind: z.literal("setExpiry"), expiresAt: z.number().int().nonnegative() }),
        ]),
      },
    },
    async ({ policyId, operation }) => {
      try {
        return json(await registry.buildUpdate(toPolicyId(policyId), operation));
      } catch (error) {
        return jsonError(error);
      }
    },
  );

  return server;
}
