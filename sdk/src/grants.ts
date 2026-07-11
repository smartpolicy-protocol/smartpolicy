import { bytesToBigInt, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { actionId, NO_CONTEXT } from "./actions.js";
import type { SmartPolicy } from "./client.js";

/** EIP-712 type for a Grant. Field order MUST match IGrantVerifier.Grant. */
export const grantTypes = {
  Grant: [
    { name: "policyId", type: "uint256" },
    { name: "subject", type: "address" },
    { name: "action", type: "bytes32" },
    { name: "issuedAt", type: "uint64" },
    { name: "expiresAt", type: "uint64" },
    { name: "nonce", type: "uint256" },
    { name: "issuer", type: "address" },
    { name: "target", type: "address" },
    { name: "context", type: "bytes32" },
  ],
} as const;

export interface Grant {
  policyId: bigint;
  subject: Address;
  action: Hex;
  issuedAt: bigint;
  expiresAt: bigint;
  nonce: bigint;
  issuer: Address;
  target: Address;
  context: Hex;
}

export interface IssuedGrant {
  /** The grant object, ready to pass (with `signature`) to a PolicyGate. */
  grant: Grant;
  signature: Hex;
  /** Solidity tuple literal for `cast send`:
   *  `fn((uint256,address,bytes32,uint64,uint64,uint256,address,address,bytes32),bytes) <tuple> <signature>` */
  tuple: string;
  requestedTtlSeconds: number;
  grantedTtlSeconds: number;
}

export interface IssueOptions {
  policyId: bigint;
  subject: Address;
  /** action name (hashed) or an already-0x bytes32 */
  action: string;
  /** the contract that will consume the grant (the PolicyGate); only it may redeem */
  target: Address;
  /** grant lifetime in seconds; keep short (minutes). Default 600. */
  ttlSeconds?: number;
  /** parameter binding — use bindContext(...). Omit for an action-level grant. */
  context?: Hex;
}

/**
 * Signs EIP-712 authorization grants. This is the "your issuers, not ours" path:
 * run your own issuer with a key the policy authorizes (registry.addIssuer), and
 * apply ANY off-chain logic you like before signing (budgets, KYC, rate limits).
 *
 * The server never needs SmartPolicy's hosted issuer — this puts issuance
 * entirely in your control.
 */
export class GrantIssuer {
  private readonly account;

  constructor(
    private readonly sp: SmartPolicy,
    privateKey: Hex,
    /** optional wall-clock (unix seconds) for deterministic testing */
    private readonly now: () => number = () => Math.floor(Date.now() / 1000),
  ) {
    this.account = privateKeyToAccount(privateKey);
  }

  /** The issuer address to authorize on a policy (registry.addIssuer). */
  get address(): Address {
    return this.account.address;
  }

  async issue(opts: IssueOptions): Promise<IssuedGrant> {
    const requested = opts.ttlSeconds ?? 600;
    const ttl = Math.max(1, requested);
    const now = this.now();
    // Backdate issuedAt so a just-issued grant is immediately valid on chains
    // whose latest block.timestamp lags real time (avoids a transient
    // GrantNotYetValid right after issuance).
    const SKEW_BUFFER = 60;
    const issuedAt = now - SKEW_BUFFER;
    const nonce = bytesToBigInt(crypto.getRandomValues(new Uint8Array(32)));
    const context = opts.context ?? NO_CONTEXT;

    const grant: Grant = {
      policyId: opts.policyId,
      subject: opts.subject,
      action: actionId(opts.action),
      issuedAt: BigInt(issuedAt),
      expiresAt: BigInt(now + ttl),
      nonce,
      issuer: this.account.address,
      target: opts.target,
      context,
    };

    const signature = await this.account.signTypedData({
      domain: {
        name: "SmartPolicy Grants",
        version: "1",
        chainId: this.sp.chainId,
        verifyingContract: this.sp.verifier,
      },
      types: grantTypes,
      primaryType: "Grant",
      message: grant,
    });

    return {
      grant,
      signature,
      tuple: `(${grant.policyId},${grant.subject},${grant.action},${grant.issuedAt},${grant.expiresAt},${grant.nonce},${grant.issuer},${grant.target},${grant.context})`,
      requestedTtlSeconds: requested,
      grantedTtlSeconds: ttl,
    };
  }
}
