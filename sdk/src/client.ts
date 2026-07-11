import {
  createPublicClient,
  encodeFunctionData,
  http,
  type Address,
  type Hex,
  type PublicClient,
} from "viem";
import { actionRuleNames, registryAbi, verifierAbi, type ActionRuleName } from "./abi.js";
import { actionId } from "./actions.js";
import { BASE_SEPOLIA, type Deployment } from "./deployments.js";
import type { Grant } from "./grants.js";

export interface SmartPolicyConfig {
  rpcUrl: string;
  chainId: number;
  registry: Address;
  verifier: Address;
}

export interface CheckResult {
  allowed: boolean;
  exists: boolean;
  active: boolean;
  rule: ActionRuleName;
  isMember: boolean;
  reasons: string[];
}

export interface PolicyInfo {
  exists: boolean;
  owner: Address;
  expiresAt: bigint; // 0 = never
  active: boolean;
  locked: boolean;
  openMembership: boolean;
  transferable: boolean;
  memberCount: bigint;
  metadataURI: string;
  metadataHash: Hex;
}

export interface UnsignedTx {
  to: Address;
  value: bigint;
  data: Hex;
}

const ZERO_HASH = `0x${"0".repeat(64)}` as Hex;

/**
 * SmartPolicy read/build client. Answer the canonical question, read policies,
 * verify grants, and build unsigned policy transactions for the caller's wallet.
 * The client never holds keys or signs a chain transaction.
 */
export class SmartPolicy {
  readonly config: SmartPolicyConfig;
  private readonly client: PublicClient;

  constructor(config: SmartPolicyConfig) {
    this.config = config;
    this.client = createPublicClient({ transport: http(config.rpcUrl) });
  }

  /** Zero-config client against a canonical deployment (default Base Sepolia). */
  static fromDeployment(d: Deployment = BASE_SEPOLIA): SmartPolicy {
    return new SmartPolicy({ rpcUrl: d.rpcUrl, chainId: d.chainId, registry: d.registry, verifier: d.verifier });
  }

  static baseSepolia(): SmartPolicy {
    return SmartPolicy.fromDeployment(BASE_SEPOLIA);
  }

  get chainId(): number {
    return this.config.chainId;
  }
  get registry(): Address {
    return this.config.registry;
  }
  get verifier(): Address {
    return this.config.verifier;
  }

  private read<T>(functionName: string, args: unknown[] = []): Promise<T> {
    return this.client.readContract({
      address: this.config.registry,
      abi: registryAbi,
      functionName: functionName as never,
      args: args as never,
    }) as Promise<T>;
  }

  // -- the canonical question ------------------------------------------------

  /** may `subject` perform `action` under `policyId`? (a single on-chain read) */
  isAllowed(policyId: bigint, subject: Address, action: string): Promise<boolean> {
    return this.read<boolean>("isAllowed", [policyId, subject, actionId(action)]);
  }

  /** isAllowed plus the reasons behind the answer. All reads pinned to one block. */
  async check(policyId: bigint, subject: Address, action: string): Promise<CheckResult> {
    const id = actionId(action);
    const blockNumber = await this.client.getBlockNumber({ cacheTime: 0 });
    const pin = (fn: string, args: unknown[]) =>
      this.client.readContract({ address: this.config.registry, abi: registryAbi, functionName: fn as never, args: args as never, blockNumber });
    const [allowed, active, count, member, ruleIdx] = (await Promise.all([
      pin("isAllowed", [policyId, subject, id]),
      pin("isPolicyActive", [policyId]),
      pin("policyCount", []),
      pin("isMember", [policyId, subject]),
      pin("getActionRule", [policyId, id]),
    ])) as [boolean, boolean, bigint, boolean, number];
    const exists = policyId >= 1n && policyId <= count;
    const rule = actionRuleNames[ruleIdx] ?? "UNSET";

    const reasons: string[] = [];
    if (!exists) reasons.push("policy does not exist");
    else if (!active) reasons.push("policy is expired");
    else {
      reasons.push(`action rule is ${rule}`);
      if (rule === "ANYONE") reasons.push("every address is allowed");
      else if (rule === "NOBODY") reasons.push("the action is disabled for everyone");
      else reasons.push(member ? "subject is a member" : "subject is not a member");
    }
    return { allowed, exists, active, rule, isMember: member, reasons };
  }

  // -- reads -----------------------------------------------------------------

  async getPolicy(policyId: bigint): Promise<PolicyInfo> {
    const count = await this.read<bigint>("policyCount");
    if (policyId < 1n || policyId > count) {
      return { exists: false, owner: `0x${"0".repeat(40)}` as Address, expiresAt: 0n, active: false, locked: false, openMembership: false, transferable: false, memberCount: 0n, metadataURI: "", metadataHash: ZERO_HASH };
    }
    const [p, active, members] = await Promise.all([
      this.read<{ owner: Address; expiresAt: bigint; flags: number; locked: boolean; metadataHash: Hex; metadataURI: string }>("getPolicy", [policyId]),
      this.read<boolean>("isPolicyActive", [policyId]),
      this.read<bigint>("memberCount", [policyId]),
    ]);
    return {
      exists: true,
      owner: p.owner,
      expiresAt: p.expiresAt,
      active,
      locked: p.locked,
      openMembership: (p.flags & 1) !== 0,
      transferable: (p.flags & 2) !== 0,
      memberCount: members,
      metadataURI: p.metadataURI,
      metadataHash: p.metadataHash,
    };
  }

  isMember(policyId: bigint, account: Address): Promise<boolean> {
    return this.read<boolean>("isMember", [policyId, account]);
  }
  isAdmin(policyId: bigint, account: Address): Promise<boolean> {
    return this.read<boolean>("isAdmin", [policyId, account]);
  }
  isOwner(policyId: bigint, account: Address): Promise<boolean> {
    return this.read<boolean>("isOwner", [policyId, account]);
  }
  isAuthorizedIssuer(policyId: bigint, issuer: Address): Promise<boolean> {
    return this.read<boolean>("isAuthorizedIssuer", [policyId, issuer]);
  }
  async fees(): Promise<{ creationFee: bigint; updateFee: bigint }> {
    const [creationFee, updateFee] = await Promise.all([this.read<bigint>("creationFee"), this.read<bigint>("updateFee")]);
    return { creationFee, updateFee };
  }

  /** Guard against a chainId/RPC mismatch that would make every grant unverifiable. */
  async assertChainId(): Promise<void> {
    const live = await this.client.getChainId();
    if (live !== this.config.chainId)
      throw new Error(`chainId mismatch: configured ${this.config.chainId} but RPC serves ${live} — grants would be unverifiable.`);
  }

  // -- grants ----------------------------------------------------------------

  /** Pre-flight a grant before broadcasting: on-chain validity + nonce freshness. */
  async verifyGrant(grant: Grant, signature: Hex): Promise<{ valid: boolean; nonceUsed: boolean }> {
    const [valid, nonceUsed] = await Promise.all([
      this.client.readContract({ address: this.config.verifier, abi: verifierAbi, functionName: "isGrantValid", args: [grant, signature] }) as Promise<boolean>,
      this.client.readContract({ address: this.config.verifier, abi: verifierAbi, functionName: "isNonceUsed", args: [grant.issuer, grant.nonce] }) as Promise<boolean>,
    ]);
    return { valid, nonceUsed };
  }

  // -- build unsigned txs (the caller signs with their own wallet) -----------

  async buildCreatePolicy(opts: { openMembership?: boolean; transferable?: boolean; expiresAt?: number; metadataURI?: string; metadataHash?: Hex } = {}): Promise<UnsignedTx> {
    const { creationFee } = await this.fees();
    const flags = (opts.openMembership ? 1 : 0) | (opts.transferable ? 2 : 0);
    return { to: this.config.registry, value: creationFee, data: encodeFunctionData({ abi: registryAbi, functionName: "createPolicy", args: [flags, BigInt(opts.expiresAt ?? 0), opts.metadataURI ?? "", opts.metadataHash ?? ZERO_HASH] }) };
  }

  private async update(functionName: string, args: unknown[]): Promise<UnsignedTx> {
    const { updateFee } = await this.fees();
    return { to: this.config.registry, value: updateFee, data: encodeFunctionData({ abi: registryAbi, functionName: functionName as never, args: args as never }) };
  }

  buildAddMembers(policyId: bigint, members: Address[]) {
    return this.update("addMembers", [policyId, members]);
  }
  buildRemoveMembers(policyId: bigint, members: Address[]) {
    return this.update("removeMembers", [policyId, members]);
  }
  buildSetActionRule(policyId: bigint, action: string, rule: ActionRuleName) {
    return this.update("setActionRule", [policyId, actionId(action), actionRuleNames.indexOf(rule)]);
  }
  buildAddIssuer(policyId: bigint, issuer: Address) {
    return this.update("addIssuer", [policyId, issuer]);
  }
  buildRemoveIssuer(policyId: bigint, issuer: Address) {
    return this.update("removeIssuer", [policyId, issuer]);
  }
  buildAddAdmin(policyId: bigint, admin: Address) {
    return this.update("addAdmin", [policyId, admin]);
  }
  buildSetExpiry(policyId: bigint, expiresAt: number) {
    return this.update("setExpiry", [policyId, BigInt(expiresAt)]);
  }
}
