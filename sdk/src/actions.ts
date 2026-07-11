import { encodeAbiParameters, keccak256, toBytes, type Hex } from "viem";

/**
 * The on-chain action identifier for a name. Actions are free-form strings
 * hashed with keccak256 — matching `keccak256("withdraw")` in a PolicyGate
 * contract. Pass an already-0x-prefixed 32-byte value through untouched.
 */
export function actionId(action: string): Hex {
  if (/^0x[0-9a-fA-F]{64}$/.test(action)) return action as Hex;
  return keccak256(toBytes(action));
}

/**
 * Compute a grant `context` binding from the exact call parameters an issuer
 * is approving. This is what turns "may sweep" into "may sweep TO this address
 * for THIS amount": the gate recomputes the same hash from the live call and
 * rejects any mismatch.
 *
 * @example bindContext(["address"], [coldWallet])
 * @example bindContext(["address","uint256"], [recipient, amount])
 *
 * The Solidity side must compute the identical value, e.g.
 *   keccak256(abi.encode(to))            // bindContext(["address"], [to])
 *   keccak256(abi.encode(to, amount))    // bindContext(["address","uint256"], [to, amount])
 */
export function bindContext(types: string[], values: unknown[]): Hex {
  const params = types.map((type) => ({ type }));
  return keccak256(encodeAbiParameters(params, values));
}

/** bytes32(0) — a grant that binds the action but not the call's parameters. */
export const NO_CONTEXT = `0x${"00".repeat(32)}` as Hex;
