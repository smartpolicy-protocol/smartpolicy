import {
  createPublicClient,
  encodeFunctionData,
  http,
  type Address,
  type Hex,
  type PublicClient,
} from "viem";
import { actionRuleNames, registryAbi, verifierAbi, type ActionRuleName } from "./abi.js";
import { toActionId } from "./actions.js";
import type { Config } from "./config.js";

/** Mirrors IGrantVerifier.Grant for the grant_verify tool. */
export interface GrantTuple {
  policyId: string | number | bigint;
  subject: Address;
  action: Hex;
  issuedAt: string | number | bigint;
  expiresAt: string | number | bigint;
  nonce: string | number | bigint;
  issuer: Address;
  target: Address;
}

export interface CheckResult {
  allowed: boolean;
  exists: boolean;
  policyId: string;
  subject: Address;
  action: string;
  actionId: Hex;
  reasons: string[];
}

export interface PolicyInfo {
  policyId: string;
  exists: boolean;
  owner: Address;
  expiresAt: string;
  active: boolean;
  locked: boolean;
  openMembership: boolean;
  transferable: boolean;
  memberCount: string;
  metadataURI: string;
  /** keccak256 commitment to the metadata document; 0x00…00 = none. Verify fetched metadata against this. */
  metadataHash: Hex;
}

/** Unsigned transaction returned to the caller to sign with their own wallet. */
export interface UnsignedTx {
  to: Address;
  value: string;
  data: Hex;
  description: string;
}

export class Registry {
  readonly client: PublicClient;

  constructor(private readonly config: Config) {
    this.client = createPublicClient({ transport: http(config.rpcUrl) });
  }

  private read<T>(functionName: string, args: unknown[] = []): Promise<T> {
    return this.client.readContract({
      address: this.config.registry,
      abi: registryAbi,
      functionName: functionName as never,
      args: args as never,
    }) as Promise<T>;
  }

  /** policy_check: the canonical question, with human/agent-readable reasons.
   *  All four reads are pinned to one block so the cosmetic reasons[] can never
   *  disagree with `allowed` under a sub-second race (N2). */
  async check(policyId: bigint, subject: Address, action: string): Promise<CheckResult> {
    const actionId = toActionId(action);
    // cacheTime: 0 — viem caches getBlockNumber for ~pollingInterval, which would
    // pin reads to a stale block and miss a just-mined update (worse than the
    // cosmetic race N2 set out to fix).
    const blockNumber = await this.client.getBlockNumber({ cacheTime: 0 });
    const pinned = (functionName: string, args: unknown[]) =>
      this.client.readContract({
        address: this.config.registry,
        abi: registryAbi,
        functionName: functionName as never,
        args: args as never,
        blockNumber,
      });
    const [allowed, active, exists, member, ruleIdx] = (await Promise.all([
      pinned("isAllowed", [policyId, subject, actionId]),
      pinned("isPolicyActive", [policyId]),
      pinned("policyCount", []).then((count) => policyId >= 1n && policyId <= (count as bigint)),
      pinned("isMember", [policyId, subject]),
      pinned("getActionRule", [policyId, actionId]),
    ])) as [boolean, boolean, boolean, boolean, number];
    const rule: ActionRuleName = actionRuleNames[ruleIdx] ?? "UNSET";

    const reasons: string[] = [];
    if (!exists) {
      reasons.push("policy does not exist");
    } else if (!active) {
      reasons.push("policy is expired");
    } else {
      reasons.push(`action rule is ${rule}`);
      if (rule === "ANYONE") reasons.push("rule ANYONE: every address is allowed");
      else if (rule === "NOBODY") reasons.push("rule NOBODY: the action is disabled for everyone");
      else reasons.push(member ? "subject is a member" : "subject is not a member");
    }

    return { allowed, exists, policyId: policyId.toString(), subject, action, actionId, reasons };
  }

  async getPolicy(policyId: bigint): Promise<PolicyInfo> {
    const count = await this.read<bigint>("policyCount");
    if (policyId < 1n || policyId > count) {
      return {
        policyId: policyId.toString(),
        exists: false,
        owner: `0x${"0".repeat(40)}` as Address,
        expiresAt: "never",
        active: false,
        locked: false,
        openMembership: false,
        transferable: false,
        memberCount: "0",
        metadataURI: "",
        metadataHash: `0x${"0".repeat(64)}` as Hex,
      };
    }
    const [policy, active, members] = await Promise.all([
      this.read<{
        owner: Address;
        expiresAt: bigint;
        flags: number;
        locked: boolean;
        metadataHash: Hex;
        metadataURI: string;
      }>("getPolicy", [policyId]),
      this.read<boolean>("isPolicyActive", [policyId]),
      this.read<bigint>("memberCount", [policyId]),
    ]);
    return {
      policyId: policyId.toString(),
      exists: true,
      owner: policy.owner,
      expiresAt: policy.expiresAt === 0n ? "never" : new Date(Number(policy.expiresAt) * 1000).toISOString(),
      active,
      locked: policy.locked,
      openMembership: (policy.flags & 1) !== 0,
      transferable: (policy.flags & 2) !== 0,
      memberCount: members.toString(),
      metadataURI: policy.metadataURI,
      metadataHash: policy.metadataHash,
    };
  }

  async fees(): Promise<{ creationFee: bigint; updateFee: bigint }> {
    const [creationFee, updateFee] = await Promise.all([
      this.read<bigint>("creationFee"),
      this.read<bigint>("updateFee"),
    ]);
    return { creationFee, updateFee };
  }

  async isAuthorizedIssuer(policyId: bigint, issuer: Address): Promise<boolean> {
    return this.read<boolean>("isAuthorizedIssuer", [policyId, issuer]);
  }

  /** M2: confirm the configured chainId matches the chain the RPC actually
   *  serves — a mismatch silently makes every issued grant's EIP-712 signature
   *  recover to the wrong address and revert on-chain. */
  async assertChainId(): Promise<void> {
    const live = await this.client.getChainId();
    if (live !== this.config.chainId) {
      throw new Error(
        `chainId mismatch: configured ${this.config.chainId} but RPC ${this.config.rpcUrl} serves ${live}. ` +
          "Fix SMARTPOLICY_CHAIN_ID or SMARTPOLICY_RPC_URL — grants would otherwise be silently unverifiable.",
      );
    }
  }

  /** grant_verify (idea #2): off-chain pre-flight of a grant before broadcast. */
  async verifyGrant(grant: GrantTuple, signature: Hex): Promise<{ valid: boolean; nonceUsed: boolean }> {
    const tuple = {
      policyId: BigInt(grant.policyId),
      subject: grant.subject,
      action: grant.action,
      issuedAt: BigInt(grant.issuedAt),
      expiresAt: BigInt(grant.expiresAt),
      nonce: BigInt(grant.nonce),
      issuer: grant.issuer,
      target: grant.target,
    };
    const [valid, nonceUsed] = await Promise.all([
      this.client.readContract({
        address: this.config.verifier,
        abi: verifierAbi,
        functionName: "isGrantValid",
        args: [tuple, signature],
      }) as Promise<boolean>,
      this.client.readContract({
        address: this.config.verifier,
        abi: verifierAbi,
        functionName: "isNonceUsed",
        args: [grant.issuer, BigInt(grant.nonce)],
      }) as Promise<boolean>,
    ]);
    return { valid, nonceUsed };
  }

  /** policy_create: build the unsigned transaction; the caller signs it. */
  async buildCreatePolicy(opts: {
    openMembership?: boolean;
    transferable?: boolean;
    expiresAt?: number;
    metadataURI?: string;
    metadataHash?: Hex;
  }): Promise<UnsignedTx> {
    const { creationFee } = await this.fees();
    const flags = (opts.openMembership ? 1 : 0) | (opts.transferable ? 2 : 0);
    const zeroHash = `0x${"0".repeat(64)}` as Hex;
    return {
      to: this.config.registry,
      value: creationFee.toString(),
      data: encodeFunctionData({
        abi: registryAbi,
        functionName: "createPolicy",
        args: [flags, BigInt(opts.expiresAt ?? 0), opts.metadataURI ?? "", opts.metadataHash ?? zeroHash],
      }),
      description:
        "createPolicy — submit from the wallet that should OWN the policy. " +
        "The new policyId is emitted in the PolicyCreated event (also: policyCount() after inclusion).",
    };
  }

  /** policy_update: build the unsigned transaction for a rule change. */
  async buildUpdate(
    policyId: bigint,
    op:
      | { kind: "addMembers"; members: Address[] }
      | { kind: "removeMembers"; members: Address[] }
      | { kind: "setActionRule"; action: string; rule: ActionRuleName }
      | { kind: "addIssuer"; issuer: Address }
      | { kind: "removeIssuer"; issuer: Address }
      | { kind: "addAdmin"; admin: Address }
      | { kind: "removeAdmin"; admin: Address }
      | { kind: "setExpiry"; expiresAt: number },
  ): Promise<UnsignedTx> {
    const { updateFee } = await this.fees();
    let data: Hex;
    switch (op.kind) {
      case "addMembers":
        data = encodeFunctionData({ abi: registryAbi, functionName: "addMembers", args: [policyId, op.members] });
        break;
      case "removeMembers":
        data = encodeFunctionData({ abi: registryAbi, functionName: "removeMembers", args: [policyId, op.members] });
        break;
      case "setActionRule":
        data = encodeFunctionData({
          abi: registryAbi,
          functionName: "setActionRule",
          args: [policyId, toActionId(op.action), actionRuleNames.indexOf(op.rule)],
        });
        break;
      case "addIssuer":
        data = encodeFunctionData({ abi: registryAbi, functionName: "addIssuer", args: [policyId, op.issuer] });
        break;
      case "removeIssuer":
        data = encodeFunctionData({ abi: registryAbi, functionName: "removeIssuer", args: [policyId, op.issuer] });
        break;
      case "addAdmin":
        data = encodeFunctionData({ abi: registryAbi, functionName: "addAdmin", args: [policyId, op.admin] });
        break;
      case "removeAdmin":
        data = encodeFunctionData({ abi: registryAbi, functionName: "removeAdmin", args: [policyId, op.admin] });
        break;
      case "setExpiry":
        data = encodeFunctionData({
          abi: registryAbi,
          functionName: "setExpiry",
          args: [policyId, BigInt(op.expiresAt)],
        });
        break;
    }
    return {
      to: this.config.registry,
      value: updateFee.toString(),
      data,
      description: `${op.kind} on policy ${policyId} — submit from the policy owner or an admin wallet.`,
    };
  }
}
