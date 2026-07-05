import { bytesToBigInt, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { toActionId } from "./actions.js";
import type { Config } from "./config.js";

/** Mirrors IGrantVerifier.Grant; field order matters for EIP-712. */
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
  ],
} as const;

export interface IssuedGrant {
  grant: {
    policyId: string;
    subject: Address;
    action: Hex;
    issuedAt: number;
    expiresAt: number;
    nonce: string;
    issuer: Address;
    target: Address;
  };
  signature: Hex;
  /** The grant as a Solidity tuple literal — paste directly into
   *  `cast send <target> "fn((uint256,address,bytes32,uint64,uint64,uint256,address,address),bytes)" <tuple> <signature>` */
  castTuple: string;
  requestedTtlSeconds: number;
  grantedTtlSeconds: number;
  ttlClamped: boolean;
  usage: string;
}

export class GrantIssuer {
  private readonly account;

  constructor(private readonly config: Config) {
    if (!config.issuerKey) throw new Error("grant issuance disabled: SMARTPOLICY_ISSUER_KEY not configured");
    this.account = privateKeyToAccount(config.issuerKey);
  }

  get address(): Address {
    return this.account.address;
  }

  /**
   * Sign a short-lived single-use grant. Random 256-bit nonces make collisions
   * within one issuer's namespace negligible without any state.
   * @param target the contract that will consume the grant (the integrator/gate).
   *        Only this address may call consumeGrant — prevents mempool griefing.
   */
  async issue(
    policyId: bigint,
    subject: Address,
    action: string,
    ttlSeconds: number,
    target: Address,
  ): Promise<IssuedGrant> {
    const ttl = Math.min(Math.max(1, ttlSeconds), this.config.maxGrantTtl);
    const now = Math.floor(Date.now() / 1000);
    // Backdate issuedAt by a small buffer so a just-issued grant is immediately
    // valid on chains whose latest block.timestamp lags real time (e.g. ~12s
    // blocks on Sepolia) — without it, on-chain `block.timestamp < issuedAt`
    // transiently reverts GrantNotYetValid right after issuance.
    const SKEW_BUFFER = 60;
    const issuedAt = now - SKEW_BUFFER;
    const nonce = bytesToBigInt(crypto.getRandomValues(new Uint8Array(32)));

    const grant = {
      policyId,
      subject,
      action: toActionId(action),
      issuedAt: BigInt(issuedAt),
      expiresAt: BigInt(now + ttl),
      nonce,
      issuer: this.account.address,
      target,
    };

    const signature = await this.account.signTypedData({
      domain: {
        name: "SmartPolicy Grants",
        version: "1",
        chainId: this.config.chainId,
        verifyingContract: this.config.verifier,
      },
      types: grantTypes,
      primaryType: "Grant",
      message: grant,
    });

    return {
      grant: {
        policyId: grant.policyId.toString(),
        subject: grant.subject,
        action: grant.action,
        issuedAt,
        expiresAt: now + ttl,
        nonce: nonce.toString(),
        issuer: grant.issuer,
        target,
      },
      signature,
      castTuple: `(${grant.policyId},${grant.subject},${grant.action},${issuedAt},${now + ttl},${nonce},${grant.issuer},${target})`,
      requestedTtlSeconds: ttlSeconds,
      grantedTtlSeconds: ttl,
      ttlClamped: ttl !== ttlSeconds,
      usage:
        "Pass (grant, signature) to the `target` contract's grant-gated function " +
        "(PolicyGate.withGrant). Only `target` may consume this grant (front-run " +
        "protection). Single-use: the nonce is consumed on first successful on-chain use.",
    };
  }
}
