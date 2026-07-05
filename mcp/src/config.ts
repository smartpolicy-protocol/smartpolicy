import type { Address, Hex } from "viem";

/**
 * All configuration comes from the environment — the server holds no user
 * keys, ever. SMARTPOLICY_ISSUER_KEY is the server's own grant-issuer key
 * and is optional: without it the grant_issue tool reports itself disabled.
 */
export interface Config {
  rpcUrl: string;
  chainId: number;
  registry: Address;
  verifier: Address;
  issuerKey?: Hex;
  /** Cap on grant lifetime, seconds. Grants should be short-lived. */
  maxGrantTtl: number;
}

/** Canonical public testnet deployment — the zero-config default. */
export const SEPOLIA_DEFAULTS = {
  rpcUrl: "https://ethereum-sepolia-rpc.publicnode.com",
  chainId: 11155111,
  registry: "0x5D127b04d344EfBfb9C127F2B598Cb824D0B8334" as Address,
  verifier: "0x3510B9427BeadD04D052E0b01248a6A6A1f23dc9" as Address,
};

/** Parse a positive-integer env var, throwing on NaN/garbage instead of
 *  silently producing NaN that corrupts the EIP-712 domain or TTL math (L6). */
function parsePositiveInt(raw: string | undefined, fallback: number, name: string): number {
  if (raw === undefined) return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0 || !Number.isInteger(n)) {
    throw new Error(`invalid ${name}: ${JSON.stringify(raw)} (must be a positive integer)`);
  }
  return n;
}

/** Validate the optional issuer key shape. A malformed key disables issuance
 *  (with a stderr warning) rather than crashing the server — free reads must
 *  keep working regardless of issuer config (L7). */
function parseIssuerKey(raw: string | undefined): Hex | undefined {
  if (!raw) return undefined;
  if (!/^0x[0-9a-fA-F]{64}$/.test(raw)) {
    console.error("WARNING: SMARTPOLICY_ISSUER_KEY is malformed (expected 0x + 64 hex chars); grant issuance disabled.");
    return undefined;
  }
  return raw as Hex;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const registry = env.SMARTPOLICY_REGISTRY;
  const verifier = env.SMARTPOLICY_VERIFIER;

  const issuerKey = parseIssuerKey(env.SMARTPOLICY_ISSUER_KEY);
  const maxGrantTtl = parsePositiveInt(env.SMARTPOLICY_MAX_GRANT_TTL, 3600, "SMARTPOLICY_MAX_GRANT_TTL");

  // Zero-config: no addresses given → run against the public Sepolia deployment.
  if (!registry && !verifier) {
    return {
      rpcUrl: env.SMARTPOLICY_RPC_URL ?? SEPOLIA_DEFAULTS.rpcUrl,
      chainId: parsePositiveInt(env.SMARTPOLICY_CHAIN_ID, SEPOLIA_DEFAULTS.chainId, "SMARTPOLICY_CHAIN_ID"),
      registry: SEPOLIA_DEFAULTS.registry,
      verifier: SEPOLIA_DEFAULTS.verifier,
      issuerKey,
      maxGrantTtl,
    };
  }

  // Custom deployment (local anvil, another network): both addresses required.
  if (!registry || !verifier) {
    throw new Error(
      "set BOTH SMARTPOLICY_REGISTRY and SMARTPOLICY_VERIFIER for a custom deployment, or neither to use the public Sepolia default",
    );
  }
  return {
    rpcUrl: env.SMARTPOLICY_RPC_URL ?? "http://127.0.0.1:8545",
    chainId: parsePositiveInt(env.SMARTPOLICY_CHAIN_ID, 31337, "SMARTPOLICY_CHAIN_ID"),
    registry: registry as Address,
    verifier: verifier as Address,
    issuerKey,
    maxGrantTtl,
  };
}
