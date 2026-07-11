import type { Address } from "viem";

export interface Deployment {
  name: string;
  chainId: number;
  rpcUrl: string;
  registry: Address;
  verifier: Address;
  explorer: string;
}

/** Canonical public deployments. Base Sepolia is the canonical testnet (v2,
 *  9-field grants with parameter binding). Mainnet is not deployed yet
 *  (pending audit — see AUDIT.md). */
export const BASE_SEPOLIA: Deployment = {
  name: "base-sepolia",
  chainId: 84532,
  rpcUrl: "https://sepolia.base.org",
  registry: "0xd91075CEe40F302aAEBa61AE1889a712879acd37",
  verifier: "0xD8aE4227f9119CcF6F198EBE9018cED7dF117535",
  explorer: "https://base-sepolia.blockscout.com",
};

export const DEPLOYMENTS: Record<string, Deployment> = {
  "base-sepolia": BASE_SEPOLIA,
};
