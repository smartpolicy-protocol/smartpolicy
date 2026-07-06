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

    /// grant is SUFFICIENT (no isAllowed) — used to test non-member authorization.
    function sufficientGrant(
        uint256 policyId,
        bytes32 action,
        bytes32 context,
        IGrantVerifier.Grant calldata grant,
        bytes calldata sig
    ) external withGrant(policyId, action, context, grant, sig) returns (bool) {
        return true;
    }

    /// two-factor: requires isAllowed AND a grant.
    function allowedGrant(
        uint256 policyId,
        bytes32 action,
        bytes32 context,
        IGrantVerifier.Grant calldata grant,
        bytes calldata sig
    ) external onlyAllowedWithGrant(policyId, action, context, grant, sig) returns (bool) {
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

        treasury = new AgentGuardedTreasury(address(registry), address(verifier), policyId, alice);
        vm.deal(agent, 10 ether);
        vm.deal(outsider, 10 ether);
    }

    /// Grant bound to sweeping to `subject` itself (context = keccak256(abi.encode(to))).
    function _signedGrant(address subject, bytes32 action, uint256 nonce)
        internal
        view
        returns (IGrantVerifier.Grant memory grant, bytes memory sig)
    {
        return _signedGrant(subject, action, nonce, keccak256(abi.encode(subject)));
    }

    function _signedGrant(address subject, bytes32 action, uint256 nonce, bytes32 context)
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
            target: address(treasury), // the gate contract that will consume the grant
            context: context
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
        // outsider steals agent's grant: fails the two-factor check (not allowed
        // on-chain) before the grant is even examined.
        vm.expectRevert(
            abi.encodeWithSelector(PolicyGate.NotAllowedByPolicy.selector, policyId, outsider, treasury.ACTION_SWEEP())
        );
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
        AgentGuardedTreasury bare = new AgentGuardedTreasury(address(registry), address(0), policyId, alice);
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
            target: address(treasury),
            context: keccak256(abi.encode(agent))
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(issuerKey, verifier.hashGrant(grant));
        vm.expectRevert(abi.encodeWithSelector(PolicyGate.GrantPolicyMismatch.selector, policyId, otherPolicy));
        vm.prank(agent);
        treasury.sweep(payable(agent), grant, abi.encodePacked(r, s, v));
    }

    // -- H-1: grant context binds the recipient (no parameter substitution) ----

    function test_sweepGrantBindsRecipient_cannotRedirect() public {
        _fund(3 ether);
        address coldWallet = makeAddr("coldWallet");
        // issuer approves a sweep to the cold wallet ONLY (context = keccak(to))
        (IGrantVerifier.Grant memory grant, bytes memory sig) =
            _signedGrant(agent, treasury.ACTION_SWEEP(), 1, keccak256(abi.encode(coldWallet)));

        // a compromised agent tries to redirect the funds to itself: reverts
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyGate.GrantContextMismatch.selector, keccak256(abi.encode(agent)), keccak256(abi.encode(coldWallet))
            )
        );
        vm.prank(agent);
        treasury.sweep(payable(agent), grant, sig);

        // the approved destination works, and receives the full balance
        vm.prank(agent);
        treasury.sweep(payable(coldWallet), grant, sig);
        assertEq(coldWallet.balance, 3 ether);
        assertEq(address(treasury).balance, 0);
    }

    // -- M-1: two-factor — on-chain revocation stops grants ---------------------

    function test_removingMemberStopsSweepGrant() public {
        _fund(1 ether);
        (IGrantVerifier.Grant memory grant, bytes memory sig) = _signedGrant(agent, treasury.ACTION_SWEEP(), 1);
        // revoke membership on-chain; the still-valid grant must no longer work
        address[] memory m = new address[](1);
        m[0] = agent;
        vm.prank(alice);
        registry.removeMembers(policyId, m);

        vm.expectRevert(
            abi.encodeWithSelector(PolicyGate.NotAllowedByPolicy.selector, policyId, agent, treasury.ACTION_SWEEP())
        );
        vm.prank(agent);
        treasury.sweep(payable(agent), grant, sig);
    }

    function test_disablingSweepActionStopsGrant() public {
        _fund(1 ether);
        bytes32 actionSweep = treasury.ACTION_SWEEP();
        (IGrantVerifier.Grant memory grant, bytes memory sig) = _signedGrant(agent, actionSweep, 1);
        vm.prank(alice);
        registry.setActionRule(policyId, actionSweep, IPolicyRegistry.ActionRule.NOBODY);

        vm.expectRevert(
            abi.encodeWithSelector(PolicyGate.NotAllowedByPolicy.selector, policyId, agent, actionSweep)
        );
        vm.prank(agent);
        treasury.sweep(payable(agent), grant, sig);
    }

    function _fund(uint256 amount) internal {
        bytes32 actionDeposit = treasury.ACTION_DEPOSIT();
        vm.prank(alice);
        registry.setActionRule(policyId, actionDeposit, IPolicyRegistry.ActionRule.ANYONE);
        vm.deal(outsider, amount);
        vm.prank(outsider);
        treasury.deposit{value: amount}();
    }
}

/// @dev Direct coverage of the two grant modifiers: withGrant is SUFFICIENT (can
///      authorize a non-member), onlyAllowedWithGrant requires membership too.
contract PolicyGateGrantModifierTest is Test {
    PolicyRegistry registry;
    GrantVerifier verifier;
    GateHarness gate;

    address alice = makeAddr("alice"); // policy owner
    address nonMember = makeAddr("nonMember");
    uint256 issuerKey;
    address issuer;
    uint256 policyId;
    bytes32 constant ACTION = keccak256("act");

    function setUp() public {
        (issuer, issuerKey) = makeAddrAndKey("issuer");
        registry = new PolicyRegistry(address(this), address(this), 0, 0, 1 ether, 1 ether);
        verifier = new GrantVerifier(address(registry));
        gate = new GateHarness(address(registry), address(verifier));
        vm.startPrank(alice);
        policyId = registry.createPolicy(0, 0, "", bytes32(0));
        registry.addIssuer(policyId, issuer);
        vm.stopPrank();
    }

    function _grant(address subject, bytes32 context, uint256 nonce)
        internal
        view
        returns (IGrantVerifier.Grant memory grant, bytes memory sig)
    {
        grant = IGrantVerifier.Grant({
            policyId: policyId,
            subject: subject,
            action: ACTION,
            issuedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + 10 minutes),
            nonce: nonce,
            issuer: issuer,
            target: address(gate),
            context: context
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(issuerKey, verifier.hashGrant(grant));
        sig = abi.encodePacked(r, s, v);
    }

    function test_withGrant_authorizesNonMember() public {
        // nonMember is NOT allowed on-chain, but a grant alone suffices
        assertFalse(registry.isAllowed(policyId, nonMember, ACTION));
        (IGrantVerifier.Grant memory grant, bytes memory sig) = _grant(nonMember, bytes32(0), 1);
        vm.prank(nonMember);
        assertTrue(gate.sufficientGrant(policyId, ACTION, bytes32(0), grant, sig));
    }

    function test_onlyAllowedWithGrant_rejectsNonMemberEvenWithGrant() public {
        (IGrantVerifier.Grant memory grant, bytes memory sig) = _grant(nonMember, bytes32(0), 1);
        vm.expectRevert(
            abi.encodeWithSelector(PolicyGate.NotAllowedByPolicy.selector, policyId, nonMember, ACTION)
        );
        vm.prank(nonMember);
        gate.allowedGrant(policyId, ACTION, bytes32(0), grant, sig);
    }

    function test_withGrant_contextMismatchReverts() public {
        bytes32 signed = keccak256("A");
        (IGrantVerifier.Grant memory grant, bytes memory sig) = _grant(nonMember, signed, 1);
        vm.expectRevert(
            abi.encodeWithSelector(PolicyGate.GrantContextMismatch.selector, keccak256("B"), signed)
        );
        vm.prank(nonMember);
        gate.sufficientGrant(policyId, ACTION, keccak256("B"), grant, sig);
    }
}
