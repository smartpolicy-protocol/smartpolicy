# Deploying SmartPolicy contracts

How to deploy the SmartPolicy core (`PolicyRegistry` + `GrantVerifier`) to any
EVM chain. The contracts are **immutable** — there is no upgrade path, so a new
version means a fresh deployment. Self-hosting the MCP server against your own
deployment is fully supported.

## Prerequisites

- A funded deployer key on the target chain (deploys 2 contracts + optional
  genesis policy; a few cents of gas on an L2).
- An RPC URL for the target chain.
- For source verification: the chain's explorer API (Blockscout needs no key).

## Option A — one command, no repo (recommended)

The published package embeds the compiled bytecode, so you don't need the repo
or Foundry:

```bash
SMARTPOLICY_DEPLOYER_KEY=0x<funded-key> \
SMARTPOLICY_RPC_URL=https://<your-chain-rpc> \
npx @smartpolicy/mcp deploy
```

It deploys both contracts, wires the verifier to the registry, and prints a JSON
block with the addresses and the env vars to run a server against them:

```json
{ "registry": "0x…", "verifier": "0x…",
  "env": { "SMARTPOLICY_REGISTRY": "0x…", "SMARTPOLICY_VERIFIER": "0x…", … } }
```

The deployer becomes the protocol owner **and** fee collector. Fees are set to
the testnet defaults (creation 0.0001 / update 0.00001 ETH; caps 0.01 / 0.001).

## Option B — from the repo with Foundry

```bash
cd contracts
forge build
# or run the deploy script:
forge script script/Deploy.s.sol --rpc-url <rpc> --broadcast --private-key 0x<key>
```

Constructor args, if deploying by hand:
- `PolicyRegistry(protocolOwner, feeCollector, creationFee, updateFee, maxCreationFee, maxUpdateFee)`
- `GrantVerifier(registryAddress)`

## Post-deploy checklist

1. **Wiring** — confirm the verifier points at the registry:
   ```bash
   cast call <verifier> "registry()(address)" --rpc-url <rpc>   # == <registry>
   ```
2. **Verify source** on the explorer (Blockscout example):
   ```bash
   forge verify-contract <registry> src/PolicyRegistry.sol:PolicyRegistry \
     --chain <id> --verifier blockscout --verifier-url https://<explorer>/api \
     --constructor-args $(cast abi-encode "constructor(address,address,uint256,uint256,uint256,uint256)" \
        <owner> <collector> 100000000000000 10000000000000 10000000000000000 1000000000000000) --watch
   forge verify-contract <verifier> src/GrantVerifier.sol:GrantVerifier \
     --chain <id> --verifier blockscout --verifier-url https://<explorer>/api \
     --constructor-args $(cast abi-encode "constructor(address)" <registry>) --watch
   ```
3. **Optional genesis policy** (policy #1):
   ```bash
   cast send <registry> "createPolicy(uint8,uint64,string,bytes32)" \
     0 0 "ipfs://<your-metadata>" $(cast keccak "ipfs://<your-metadata>") \
     --value 100000000000000 --private-key 0x<key> --rpc-url <rpc>
   ```
4. **Point a server/client at it** — set `SMARTPOLICY_REGISTRY`,
   `SMARTPOLICY_VERIFIER`, `SMARTPOLICY_RPC_URL`, `SMARTPOLICY_CHAIN_ID` (see
   `mcp/README.md`).

## Grant format note (v2)

Since v0.2.0 the `Grant` struct has **9 fields** (added `bytes32 context` for
parameter binding). The off-chain signer (`@smartpolicy/mcp` ≥ 0.2.0) and the
on-chain `GrantVerifier` must match — an older 8-field signer will not verify
against a v2 verifier. If you deploy v2 contracts, run a v2 (≥0.2.0) server.

## Current deployments

See `contracts/deployments/*.json`. Base Sepolia is the canonical testnet.
Mainnet: not deployed (pending audit — see `AUDIT.md`).
