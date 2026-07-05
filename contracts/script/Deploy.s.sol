// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {GrantVerifier} from "../src/GrantVerifier.sol";

/// @notice Deploys the core protocol. The broadcaster becomes protocol owner
///         and fee collector (rotate both after deploy on real networks).
///
/// Local:   forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 \
///            --broadcast --private-key $PRIVATE_KEY
/// Sepolia: same, plus --verify. Record addresses in deployments/.
contract Deploy is Script {
    // Testnet/local defaults; decide mainnet numbers before that deploy (PLAN.md).
    uint256 constant CREATION_FEE = 0.0001 ether;
    uint256 constant UPDATE_FEE = 0.00001 ether;
    uint256 constant MAX_CREATION_FEE = 0.01 ether;
    uint256 constant MAX_UPDATE_FEE = 0.001 ether;

    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);

        vm.startBroadcast(deployerKey);
        PolicyRegistry registry =
            new PolicyRegistry(deployer, deployer, CREATION_FEE, UPDATE_FEE, MAX_CREATION_FEE, MAX_UPDATE_FEE);
        GrantVerifier verifier = new GrantVerifier(address(registry));
        vm.stopBroadcast();

        console2.log("PolicyRegistry:", address(registry));
        console2.log("GrantVerifier: ", address(verifier));
    }
}
