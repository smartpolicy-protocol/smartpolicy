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
    { name: "context", type: "bytes32" },
  ],
} as const;

/** bytes32(0) — a grant that binds the action but not the call's parameters. */
export const NO_CONTEXT = `0x${"00".repeat(32)}` as Hex;

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
    context: Hex;
  };
  signature: Hex;
  /** The grant as a Solidity tuple literal — paste directly into
   *  `cast send <target> "fn((uint256,address,bytes32,uint64,uint64,uint256,address,address,bytes32),bytes)" <tuple> <signature>` */
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
   * @param context optional binding of the gated call's sensitive parameters
   *        (bytes32, default NO_CONTEXT). When set to keccak256(abi.encode(...))
   *        of the exact parameters, the gate (onlyAllowedWithGrant / withGrant
   *        with a matching context) rejects any other parameters — so an issuer
   *        approves "sweep to X", not merely "sweep".
   */
  async issue(
    policyId: bigint,
    subject: Address,
    action: string,
    ttlSeconds: number,
    target: Address,
    context: Hex = NO_CONTEXT,
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
      context,
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
        context,
      },
      signature,
      castTuple: `(${grant.policyId},${grant.subject},${grant.action},${issuedAt},${now + ttl},${nonce},${grant.issuer},${target},${context})`,
      requestedTtlSeconds: ttlSeconds,
      grantedTtlSeconds: ttl,
      ttlClamped: ttl !== ttlSeconds,
      usage:
        "Pass (grant, signature) to the `target` contract's grant-gated function " +
        "(PolicyGate.onlyAllowedWithGrant / withGrant). Only `target` may consume this grant " +
        "(front-run protection). Single-use: the nonce is consumed on first successful on-chain use. " +
        "If context != 0x00…, the gated call's parameters must match keccak256(abi.encode(...)) of what the issuer signed.",
    };
  }
}
