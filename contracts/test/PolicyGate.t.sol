// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {GrantVerifier} from "../src/GrantVerifier.sol";
import {PolicyGate} from "../src/PolicyGate.sol";
import {IPolicyRegistry} from "../src/interfaces/IPolicyRegistry.sol";
import {IGrantVerifier} from "../src/interfaces/IGrantVerifier.sol";
import {AgentGuardedTreasury} from "../src/examples/AgentGuardedTreasury.sol";

/// @dev Exposes each gating modifier as a callable function for direct testing.
contract GateHarness is PolicyGate {
    constructor(address registry_, address verifier_) PolicyGate(registry_, verifier_) {}

    function memberOnly(uint256 policyId) external onlyPolicyMember(policyId) returns (bool) {
        return true;
    }

    function adminOnly(uint256 policyId) external onlyPolicyAdmin(policyId) returns (bool) {
        return true;
    }

    function activeOnly(uint256 policyId) external whenPolicyActive(policyId) returns (bool) {
        return true;
    }
}

contract PolicyGateModifierTest is Test {
    PolicyRegistry registry;
    GateHarness gate;

    address alice = makeAddr("alice"); // owner
    address admin = makeAddr("admin");
    address member = makeAddr("member");
    address outsider = makeAddr("outsider");
    uint256 policyId;

    function setUp() public {
        registry = new PolicyRegistry(address(this), address(this), 0, 0, 1 ether, 1 ether);
        gate = new GateHarness(address(registry), address(0));
        vm.startPrank(alice);
        policyId = registry.createPolicy(0, 0, "", bytes32(0));
        registry.addAdmin(policyId, admin);
        address[] memory m = new address[](1);
        m[0] = member;
        registry.addMembers(policyId, m);
        vm.stopPrank();
    }

    function test_onlyPolicyAdmin_ownerPasses() public {
        vm.prank(alice);
        assertTrue(gate.adminOnly(policyId));
    }

    function test_onlyPolicyAdmin_adminPasses() public {
        vm.prank(admin);
        assertTrue(gate.adminOnly(policyId));
    }

    function test_onlyPolicyAdmin_memberReverts() public {
        vm.expectRevert(abi.encodeWithSelector(PolicyGate.NotPolicyAdmin.selector, policyId, member));
        vm.prank(member);
        gate.adminOnly(policyId);
    }

    function test_onlyPolicyMember_memberPassesOutsiderReverts() public {
        vm.prank(member);
        assertTrue(gate.memberOnly(policyId));
        vm.expectRevert(abi.encodeWithSelector(PolicyGate.NotPolicyMember.selector, policyId, outsider));
        vm.prank(outsider);
        gate.memberOnly(policyId);
    }

    function test_whenPolicyActive_passesThenRevertsAfterExpiry() public {
        vm.prank(alice);
        registry.setExpiry(policyId, uint64(block.timestamp + 1 days));
        assertTrue(gate.activeOnly(policyId));
        vm.warp(block.timestamp + 1 days + 1);
        vm.expectRevert(abi.encodeWithSelector(PolicyGate.PolicyNotActive.selector, policyId));
        gate.activeOnly(policyId);
        // member/admin gates also dead once expired
        vm.expectRevert(abi.encodeWithSelector(PolicyGate.PolicyNotActive.selector, policyId));
        vm.prank(member);
        gate.memberOnly(policyId);
    }

    function test_constructor_rejectsMismatchedVerifierRegistry() public {
        // a verifier bound to a DIFFERENT registry must be rejected (L1)
        PolicyRegistry otherRegistry = new PolicyRegistry(address(this), address(this), 0, 0, 1 ether, 1 ether);
        GrantVerifier verifierForOther = new GrantVerifier(address(otherRegistry));
        vm.expectRevert(
            abi.encodeWithSelector(PolicyGate.RegistryMismatch.selector, address(registry), address(otherRegistry))
        );
        new GateHarness(address(registry), address(verifierForOther));
    }

    function test_constructor_acceptsMatchingVerifierRegistry() public {
        GrantVerifier verifierForSame = new GrantVerifier(address(registry));
        GateHarness ok = new GateHarness(address(registry), address(verifierForSame));
        assertEq(address(ok.policyGrantVerifier()), address(verifierForSame));
    }
}

contract PolicyGateTest is Test {
    PolicyRegistry registry;
    GrantVerifier verifier;
    AgentGuardedTreasury treasury;

    address alice = makeAddr("alice"); // policy owner
    address agent = makeAddr("agent"); // authorized agent (member)
    address outsider = makeAddr("outsider");
    uint256 issuerKey;
    address issuer;

    uint256 policyId;

    function setUp() public {
        (issuer, issuerKey) = makeAddrAndKey("issuer");
        registry = new PolicyRegistry(address(this), address(this), 0, 0, 1 ether, 1 ether);
        verifier = new GrantVerifier(address(registry));

        vm.startPrank(alice);
        policyId = registry.createPolicy(0, 0, "", bytes32(0));
        address[] memory members = new address[](1);
        members[0] = agent;
        registry.addMembers(policyId, members);
        registry.addIssuer(policyId, issuer);
        vm.stopPrank();

        treasury = new AgentGuardedTreasury(address(registry), address(verifier), policyId);
        vm.deal(agent, 10 ether);
        vm.deal(outsider, 10 ether);
    }

    function _signedGrant(address subject, bytes32 action, uint256 nonce)
        internal
        view
        returns (IGrantVerifier.Grant memory grant, bytes memory sig)
    {
        grant = IGrantVerifier.Grant({
            policyId: policyId,
            subject: subject,
            action: action,
            issuedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + 10 minutes),
            nonce: nonce,
            issuer: issuer,
            target: address(treasury) // the gate contract that will consume the grant
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(issuerKey, verifier.hashGrant(grant));
        sig = abi.encodePacked(r, s, v);
    }

    // -- onlyAllowed (the canonical modifier) -------------------------------

    function test_memberPassesGate() public {
        vm.prank(agent);
        treasury.withdraw{gas: 200000}(payable(agent), 0);
    }

    function test_outsiderBlocked() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyGate.NotAllowedByPolicy.selector, policyId, outsider, treasury.ACTION_WITHDRAW()
            )
        );
        vm.prank(outsider);
        treasury.withdraw(payable(outsider), 0);
    }

    function test_actionRuleChangesGateWithoutRedeploy() public {
        bytes32 actionDeposit = treasury.ACTION_DEPOSIT();
        // open deposits to anyone via a registry update — no treasury change
        vm.expectRevert(); // outsider cannot deposit yet
        vm.prank(outsider);
        treasury.deposit{value: 1 ether}();

        vm.prank(alice);
        registry.setActionRule(policyId, actionDeposit, IPolicyRegistry.ActionRule.ANYONE);

        vm.prank(outsider);
        treasury.deposit{value: 1 ether}();
        assertEq(address(treasury).balance, 1 ether);
    }

    function test_removingMemberRevokesAccessInstantly() public {
        vm.prank(agent);
        treasury.withdraw(payable(agent), 0); // works

        address[] memory members = new address[](1);
        members[0] = agent;
        vm.prank(alice);
        registry.removeMembers(policyId, members);

        vm.expectRevert();
        vm.prank(agent);
        treasury.withdraw(payable(agent), 0);
    }

    function test_disablingActionBlocksEveryoneInstantly() public {
        bytes32 actionWithdraw = treasury.ACTION_WITHDRAW();
        vm.prank(alice);
        registry.setActionRule(policyId, actionWithdraw, IPolicyRegistry.ActionRule.NOBODY);
        vm.expectRevert();
        vm.prank(agent);
        treasury.withdraw(payable(agent), 0);
    }

    // -- withGrant -----------------------------------------------------------

    function test_sweepWithValidGrant() public {
        bytes32 actionDeposit = treasury.ACTION_DEPOSIT();
        vm.prank(alice);
        registry.setActionRule(policyId, actionDeposit, IPolicyRegistry.ActionRule.ANYONE);
        vm.prank(outsider);
        treasury.deposit{value: 3 ether}();

        (IGrantVerifier.Grant memory grant, bytes memory sig) = _signedGrant(agent, treasury.ACTION_SWEEP(), 1);
        vm.prank(agent);
        treasury.sweep(payable(agent), grant, sig);
        assertEq(address(treasury).balance, 0);
        assertEq(agent.balance, 13 ether);
    }

    function test_grantBoundToCaller() public {
        (IGrantVerifier.Grant memory grant, bytes memory sig) = _signedGrant(agent, treasury.ACTION_SWEEP(), 1);
        // outsider steals agent's grant: must fail
        vm.expectRevert(abi.encodeWithSelector(PolicyGate.GrantNotForCaller.selector, agent, outsider));
        vm.prank(outsider);
        treasury.sweep(payable(outsider), grant, sig);
    }

    function test_grantIsSingleUse() public {
        (IGrantVerifier.Grant memory grant, bytes memory sig) = _signedGrant(agent, treasury.ACTION_SWEEP(), 1);
        vm.startPrank(agent);
        treasury.sweep(payable(agent), grant, sig);
        vm.expectRevert(IGrantVerifier.GrantNonceUsed.selector);
        treasury.sweep(payable(agent), grant, sig);
        vm.stopPrank();
    }

    function test_gateWithoutVerifierRejectsGrants() public {
        AgentGuardedTreasury bare = new AgentGuardedTreasury(address(registry), address(0), policyId);
        (IGrantVerifier.Grant memory grant, bytes memory sig) = _signedGrant(agent, bare.ACTION_SWEEP(), 2);
        vm.expectRevert(PolicyGate.GrantVerifierNotConfigured.selector);
        vm.prank(agent);
        bare.sweep(payable(agent), grant, sig);
    }

    function test_grantForDifferentActionRejected() public {
        // a validly-signed grant for "deposit" must NOT redeem against sweep
        bytes32 actionDeposit = treasury.ACTION_DEPOSIT();
        bytes32 actionSweep = treasury.ACTION_SWEEP();
        (IGrantVerifier.Grant memory grant, bytes memory sig) = _signedGrant(agent, actionDeposit, 3);
        vm.expectRevert(abi.encodeWithSelector(PolicyGate.GrantActionMismatch.selector, actionSweep, actionDeposit));
        vm.prank(agent);
        treasury.sweep(payable(agent), grant, sig);
    }

    function test_grantForDifferentPolicyRejected() public {
        // second policy, same issuer authorized there too
        vm.startPrank(alice);
        uint256 otherPolicy = registry.createPolicy(0, 0, "", bytes32(0));
        registry.addIssuer(otherPolicy, issuer);
        vm.stopPrank();

        bytes32 actionSweep = treasury.ACTION_SWEEP();
        IGrantVerifier.Grant memory grant = IGrantVerifier.Grant({
            policyId: otherPolicy,
            subject: agent,
            action: actionSweep,
            issuedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + 10 minutes),
            nonce: 4,
            issuer: issuer,
            target: address(treasury)
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(issuerKey, verifier.hashGrant(grant));
        vm.expectRevert(abi.encodeWithSelector(PolicyGate.GrantPolicyMismatch.selector, policyId, otherPolicy));
        vm.prank(agent);
        treasury.sweep(payable(agent), grant, abi.encodePacked(r, s, v));
    }
}
