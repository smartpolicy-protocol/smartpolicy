/**
 * `smartpolicy-mcp deploy` — bootstrap a SmartPolicy deployment on a local or
 * custom chain without the protocol repo. Deploys PolicyRegistry +
 * GrantVerifier from embedded bytecode and prints the env vars to use.
 *
 * Required env: SMARTPOLICY_DEPLOYER_KEY (funded key on the target chain).
 * Optional env: SMARTPOLICY_RPC_URL (default http://127.0.0.1:8545).
 * The deployer becomes protocol owner and fee collector.
 */
import { createWalletClient, http, parseAbi, parseEther, publicActions } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";
import { registryBytecode, verifierBytecode } from "./deployArtifacts.js";

// Testnet/local defaults — match contracts/script/Deploy.s.sol.
const CREATION_FEE = parseEther("0.0001");
const UPDATE_FEE = parseEther("0.00001");
const MAX_CREATION_FEE = parseEther("0.01");
const MAX_UPDATE_FEE = parseEther("0.001");

const registryConstructorAbi = parseAbi([
  "constructor(address protocolOwner, address feeCollector, uint256 creationFee, uint256 updateFee, uint256 maxCreationFee, uint256 maxUpdateFee)",
]);
const verifierConstructorAbi = parseAbi(["constructor(address registry)"]);

export async function deploy(): Promise<void> {
  const key = process.env.SMARTPOLICY_DEPLOYER_KEY as Hex | undefined;
  if (!key) {
    console.error("SMARTPOLICY_DEPLOYER_KEY is required (a funded private key on the target chain)");
    process.exitCode = 1; // no process.exit(): see index.ts note on the Windows libuv race
    return;
  }
  const rpcUrl = process.env.SMARTPOLICY_RPC_URL ?? "http://127.0.0.1:8545";
  const account = privateKeyToAccount(key);
  const client = createWalletClient({ account, transport: http(rpcUrl) }).extend(publicActions);
  const chainId = await client.getChainId();

  console.error(`deploying to ${rpcUrl} (chainId ${chainId}) as ${account.address} ...`);

  const registryHash = await client.deployContract({
    abi: registryConstructorAbi,
    bytecode: registryBytecode as Hex,
    args: [account.address, account.address, CREATION_FEE, UPDATE_FEE, MAX_CREATION_FEE, MAX_UPDATE_FEE],
    chain: null,
  });
  const registryReceipt = await client.waitForTransactionReceipt({ hash: registryHash });
  if (registryReceipt.status !== "success" || !registryReceipt.contractAddress) {
    throw new Error(`PolicyRegistry deployment reverted (tx ${registryHash})`);
  }
  const registry = registryReceipt.contractAddress;

  const verifierHash = await client.deployContract({
    abi: verifierConstructorAbi,
    bytecode: verifierBytecode as Hex,
    args: [registry],
    chain: null,
  });
  const verifierReceipt = await client.waitForTransactionReceipt({ hash: verifierHash });
  if (verifierReceipt.status !== "success" || !verifierReceipt.contractAddress) {
    throw new Error(`GrantVerifier deployment reverted (tx ${verifierHash})`);
  }
  const verifier = verifierReceipt.contractAddress;

  // stdout gets machine-readable JSON; progress went to stderr
  console.log(
    JSON.stringify(
      {
        chainId,
        registry,
        verifier,
        protocolOwner: account.address,
        feeCollector: account.address,
        fees: { creationFee: CREATION_FEE.toString(), updateFee: UPDATE_FEE.toString() },
        env: {
          SMARTPOLICY_RPC_URL: rpcUrl,
          SMARTPOLICY_CHAIN_ID: String(chainId),
          SMARTPOLICY_REGISTRY: registry,
          SMARTPOLICY_VERIFIER: verifier,
        },
      },
      null,
      2,
    ),
  );
}
