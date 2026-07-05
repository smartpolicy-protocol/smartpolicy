import { keccak256, toBytes, type Hex } from "viem";

/**
 * Agents refer to actions by plain name ("withdraw", "sweep") — the protocol
 * uses bytes32. Accept either: a 0x-prefixed 32-byte hex is passed through,
 * anything else is keccak256-hashed, matching the Solidity convention
 * `keccak256("withdraw")` used by protected contracts.
 */
export function toActionId(action: string): Hex {
  if (/^0x[0-9a-fA-F]{64}$/.test(action)) return action as Hex;
  return keccak256(toBytes(action));
}

/** Same convention for condition keys. */
export const toConditionKey = toActionId;
