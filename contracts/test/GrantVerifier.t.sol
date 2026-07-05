// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {GrantVerifier} from "../src/GrantVerifier.sol";
import {IGrantVerifier} from "../src/interfaces/IGrantVerifier.sol";

contract GrantVerifierTest is Test {
    PolicyRegistry registry;
    GrantVerifier verifier;

    address alice = makeAddr("alice"); // policy owner
    address agent = makeAddr("agent"); // grant subject
    uint256 issuerKey;
    address issuer;
    uint256 rogueKey;
    address rogue;

    uint256 policyId;
    bytes32 constant ACTION = keccak256("sweep");

    function setUp() public {
        (issuer, issuerKey) = makeAddrAndKey("issuer");
        (rogue, rogueKey) = makeAddrAndKey("rogue");
        registry = new PolicyRegistry(address(this), address(this), 0, 0, 1 ether, 1 ether);
        verifier = new GrantVerifier(address(registry));

        vm.startPrank(alice);
        policyId = registry.createPolicy(0, 0, "", bytes32(0));
        registry.addIssuer(policyId, issuer);
        vm.stopPrank();
    }

    function _grant(uint256 nonce) internal view returns (IGrantVerifier.Grant memory) {
        return IGrantVerifier.Grant({
            policyId: policyId,
            subject: agent,
            action: ACTION,
            issuedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + 10 minutes),
            nonce: nonce,
            issuer: issuer,
            target: address(this) // this test contract calls consumeGrant directly
        });
    }

    function _sign(IGrantVerifier.Grant memory grant, uint256 key) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, verifier.hashGrant(grant));
        return abi.encodePacked(r, s, v);
    }

    // -- happy path ---------------------------------------------------------

    function test_validGrantVerifiesAndConsumes() public {
        IGrantVerifier.Grant memory grant = _grant(1);
        bytes memory sig = _sign(grant, issuerKey);

        assertTrue(verifier.isGrantValid(grant, sig));
        assertFalse(verifier.isNonceUsed(issuer, 1));

        vm.expectEmit(true, true, true, true);
        emit IGrantVerifier.GrantConsumed(policyId, agent, ACTION, issuer, 1);
        verifier.consumeGrant(grant, sig);

        assertTrue(verifier.isNonceUsed(issuer, 1));
    }

    function test_consumedGrantCannotBeReplayed() public {
        IGrantVerifier.Grant memory grant = _grant(1);
        bytes memory sig = _sign(grant, issuerKey);
        verifier.consumeGrant(grant, sig);

        assertFalse(verifier.isGrantValid(grant, sig));
        vm.expectRevert(IGrantVerifier.GrantNonceUsed.selector);
        verifier.consumeGrant(grant, sig);
    }

    // -- validity window ------------------------------------------------------

    function test_expiredGrantRejected() public {
        IGrantVerifier.Grant memory grant = _grant(1);
        bytes memory sig = _sign(grant, issuerKey);
        vm.warp(block.timestamp + 11 minutes);
        assertFalse(verifier.isGrantValid(grant, sig));
        vm.expectRevert(IGrantVerifier.GrantExpired.selector);
        verifier.consumeGrant(grant, sig);
    }

    function test_futureGrantRejected() public {
        IGrantVerifier.Grant memory grant = _grant(1);
        grant.issuedAt = uint64(block.timestamp + 1 hours);
        grant.expiresAt = uint64(block.timestamp + 2 hours);
        bytes memory sig = _sign(grant, issuerKey);
        vm.expectRevert(IGrantVerifier.GrantNotYetValid.selector);
        verifier.consumeGrant(grant, sig);
    }

    // -- issuer authorization ---------------------------------------------------

    function test_unauthorizedIssuerRejected() public {
        IGrantVerifier.Grant memory grant = _grant(1);
        grant.issuer = rogue;
        bytes memory sig = _sign(grant, rogueKey); // correctly signed, wrong issuer
        assertFalse(verifier.isGrantValid(grant, sig));
        vm.expectRevert(IGrantVerifier.GrantIssuerNotAuthorized.selector);
        verifier.consumeGrant(grant, sig);
    }

    function test_revokedIssuerRejected() public {
        IGrantVerifier.Grant memory grant = _grant(1);
        bytes memory sig = _sign(grant, issuerKey);
        vm.prank(alice);
        registry.removeIssuer(policyId, issuer);
        vm.expectRevert(IGrantVerifier.GrantIssuerNotAuthorized.selector);
        verifier.consumeGrant(grant, sig);
    }

    // -- signature ----------------------------------------------------------------

    function test_wrongSignerRejected() public {
        IGrantVerifier.Grant memory grant = _grant(1);
        bytes memory sig = _sign(grant, rogueKey); // claims issuer, signed by rogue
        assertFalse(verifier.isGrantValid(grant, sig));
        vm.expectRevert(IGrantVerifier.GrantSignatureInvalid.selector);
        verifier.consumeGrant(grant, sig);
    }

    function test_tamperedFieldRejected() public {
        IGrantVerifier.Grant memory grant = _grant(1);
        bytes memory sig = _sign(grant, issuerKey);
        grant.subject = rogue; // tamper after signing
        vm.expectRevert(IGrantVerifier.GrantSignatureInvalid.selector);
        verifier.consumeGrant(grant, sig);
    }

    function test_garbageSignatureRejectedNotReverted() public view {
        IGrantVerifier.Grant memory grant = _grant(1);
        assertFalse(verifier.isGrantValid(grant, hex"deadbeef"));
    }

    // -- policy state --------------------------------------------------------------

    function test_inactivePolicyRejected() public {
        vm.prank(alice);
        registry.setExpiry(policyId, uint64(block.timestamp + 1 days));
        IGrantVerifier.Grant memory grant = _grant(1);
        grant.expiresAt = uint64(block.timestamp + 2 days);
        bytes memory sig = _sign(grant, issuerKey);

        vm.warp(block.timestamp + 1 days + 1);
        assertFalse(verifier.isGrantValid(grant, sig));
        vm.expectRevert(IGrantVerifier.GrantPolicyInactive.selector);
        verifier.consumeGrant(grant, sig);
    }

    // -- nonce namespacing -----------------------------------------------------------

    function test_noncesAreNamespacedPerIssuer() public {
        vm.prank(alice);
        registry.addIssuer(policyId, rogue);

        IGrantVerifier.Grant memory grantA = _grant(7);
        verifier.consumeGrant(grantA, _sign(grantA, issuerKey));

        // same nonce, different issuer: must still work
        IGrantVerifier.Grant memory grantB = _grant(7);
        grantB.issuer = rogue;
        verifier.consumeGrant(grantB, _sign(grantB, rogueKey));

        assertTrue(verifier.isNonceUsed(issuer, 7));
        assertTrue(verifier.isNonceUsed(rogue, 7));
    }

    function testFuzz_onlyIssuerSignedGrantsPass(uint256 signerKey) public view {
        signerKey = bound(signerKey, 1, type(uint128).max);
        vm.assume(vm.addr(signerKey) != issuer);
        IGrantVerifier.Grant memory grant = _grant(1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, verifier.hashGrant(grant));
        assertFalse(verifier.isGrantValid(grant, abi.encodePacked(r, s, v)));
    }

    // -- target binding (M1: front-running DoS prevention) -----------------------

    function test_onlyTargetCanConsume() public {
        IGrantVerifier.Grant memory grant = _grant(1); // target = address(this)
        bytes memory sig = _sign(grant, issuerKey);

        // an arbitrary front-runner cannot burn the nonce
        vm.expectRevert(IGrantVerifier.GrantTargetMismatch.selector);
        vm.prank(rogue);
        verifier.consumeGrant(grant, sig);

        // the bound target still consumes successfully afterwards
        verifier.consumeGrant(grant, sig);
        assertTrue(verifier.isNonceUsed(issuer, 1));
    }

    function test_wrongTargetRejectedEvenForCorrectCaller() public {
        IGrantVerifier.Grant memory grant = _grant(1);
        grant.target = rogue; // signed for a different target than the caller (this)
        bytes memory sig = _sign(grant, issuerKey);
        vm.expectRevert(IGrantVerifier.GrantTargetMismatch.selector);
        verifier.consumeGrant(grant, sig);
    }

    // -- validity-window boundaries (L5) -----------------------------------------

    function test_validAtExactIssuedAt() public {
        IGrantVerifier.Grant memory grant = _grant(1);
        grant.issuedAt = uint64(block.timestamp); // valid at exactly issuedAt
        bytes memory sig = _sign(grant, issuerKey);
        assertTrue(verifier.isGrantValid(grant, sig));
    }

    function test_invalidOneSecondBeforeIssuedAt() public {
        IGrantVerifier.Grant memory grant = _grant(1);
        grant.issuedAt = uint64(block.timestamp + 1);
        grant.expiresAt = uint64(block.timestamp + 10 minutes);
        bytes memory sig = _sign(grant, issuerKey);
        vm.expectRevert(IGrantVerifier.GrantNotYetValid.selector);
        verifier.consumeGrant(grant, sig);
    }

    function test_validAtExactExpiresAt() public {
        IGrantVerifier.Grant memory grant = _grant(1);
        bytes memory sig = _sign(grant, issuerKey);
        vm.warp(grant.expiresAt); // exactly at expiry is still valid (strict >)
        assertTrue(verifier.isGrantValid(grant, sig));
    }

    function test_invalidOneSecondAfterExpiresAt() public {
        IGrantVerifier.Grant memory grant = _grant(1);
        bytes memory sig = _sign(grant, issuerKey);
        vm.warp(uint256(grant.expiresAt) + 1);
        vm.expectRevert(IGrantVerifier.GrantExpired.selector);
        verifier.consumeGrant(grant, sig);
    }
}
