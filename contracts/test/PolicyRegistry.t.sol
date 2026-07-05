// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {IPolicyRegistry, FLAG_OPEN_MEMBERSHIP, FLAG_TRANSFERABLE} from "../src/interfaces/IPolicyRegistry.sol";

/// @dev Reverts on any incoming ETH — used to exercise the FeeTransferFailed path.
contract RejectEther {
    receive() external payable {
        revert("nope");
    }
}

contract PolicyRegistryTest is Test {
    PolicyRegistry registry;

    address protocolOwner = makeAddr("protocolOwner");
    address collector = makeAddr("collector");
    address alice = makeAddr("alice"); // policy owner
    address bob = makeAddr("bob"); // admin
    address carol = makeAddr("carol"); // member
    address mallory = makeAddr("mallory"); // outsider

    uint256 constant CREATION_FEE = 0.001 ether;
    uint256 constant UPDATE_FEE = 0.0001 ether;
    uint256 constant MAX_CREATION_FEE = 0.01 ether;
    uint256 constant MAX_UPDATE_FEE = 0.001 ether;

    bytes32 constant ACTION = keccak256("withdraw");

    function setUp() public {
        registry = new PolicyRegistry(protocolOwner, collector, CREATION_FEE, UPDATE_FEE, MAX_CREATION_FEE, MAX_UPDATE_FEE);
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
        vm.deal(mallory, 100 ether);
    }

    // -- helpers ----------------------------------------------------------

    function _createPolicy(uint8 flags) internal returns (uint256 id) {
        vm.prank(alice);
        id = registry.createPolicy{value: CREATION_FEE}(flags, 0, "ipfs://meta", keccak256("meta-doc"));
    }

    function _addMember(uint256 id, address member) internal {
        address[] memory members = new address[](1);
        members[0] = member;
        vm.prank(alice);
        registry.addMembers{value: UPDATE_FEE}(id, members);
    }

    // -- creation ---------------------------------------------------------

    function test_createPolicy_assignsSequentialIdsFromOne() public {
        uint256 first = _createPolicy(0);
        uint256 second = _createPolicy(0);
        assertEq(first, 1);
        assertEq(second, 2);
        assertEq(registry.policyCount(), 2);
    }

    function test_createPolicy_storesFields() public {
        vm.prank(alice);
        uint256 id = registry.createPolicy{value: CREATION_FEE}(FLAG_TRANSFERABLE, uint64(block.timestamp + 1 days), "ipfs://meta", keccak256("meta-doc"));
        IPolicyRegistry.Policy memory p = registry.getPolicy(id);
        assertEq(p.owner, alice);
        assertEq(p.expiresAt, uint64(block.timestamp + 1 days));
        assertEq(p.flags, FLAG_TRANSFERABLE);
        assertFalse(p.locked);
        assertEq(p.metadataURI, "ipfs://meta");
    }

    function test_createPolicy_emitsEvent() public {
        vm.expectEmit(true, true, false, true);
        emit IPolicyRegistry.PolicyCreated(1, alice, 0, 0);
        vm.prank(alice);
        registry.createPolicy{value: CREATION_FEE}(0, 0, "", bytes32(0));
    }

    function test_createPolicy_revertsOnWrongFee() public {
        vm.expectRevert(abi.encodeWithSelector(IPolicyRegistry.WrongFee.selector, CREATION_FEE, CREATION_FEE - 1));
        vm.prank(alice);
        registry.createPolicy{value: CREATION_FEE - 1}(0, 0, "", bytes32(0));
    }

    function test_getPolicy_revertsForUnknownId() public {
        vm.expectRevert(abi.encodeWithSelector(IPolicyRegistry.PolicyNotFound.selector, 99));
        registry.getPolicy(99);
    }

    function test_metadataHash_storedAndAtomicallyUpdated() public {
        uint256 id = _createPolicy(0);
        assertEq(registry.getPolicy(id).metadataHash, keccak256("meta-doc"));

        vm.expectEmit(true, false, false, true);
        emit IPolicyRegistry.PolicyMetadataUpdated(id, "ipfs://v2", keccak256("meta-doc-v2"));
        vm.prank(alice);
        registry.setMetadataURI{value: UPDATE_FEE}(id, "ipfs://v2", keccak256("meta-doc-v2"));

        IPolicyRegistry.Policy memory p = registry.getPolicy(id);
        assertEq(p.metadataURI, "ipfs://v2");
        assertEq(p.metadataHash, keccak256("meta-doc-v2"));
    }

    // -- isAllowed: the canonical question ---------------------------------

    function test_isAllowed_memberByDefaultRule() public {
        uint256 id = _createPolicy(0);
        _addMember(id, carol);
        assertTrue(registry.isAllowed(id, carol, ACTION));
        assertFalse(registry.isAllowed(id, mallory, ACTION));
    }

    function test_isAllowed_openMembershipAllowsAnyone() public {
        uint256 id = _createPolicy(FLAG_OPEN_MEMBERSHIP);
        assertTrue(registry.isAllowed(id, mallory, ACTION));
    }

    function test_isAllowed_anyoneRuleOverridesMembership() public {
        uint256 id = _createPolicy(0);
        vm.prank(alice);
        registry.setActionRule{value: UPDATE_FEE}(id, ACTION, IPolicyRegistry.ActionRule.ANYONE);
        assertTrue(registry.isAllowed(id, mallory, ACTION));
    }

    function test_isAllowed_nobodyRuleBlocksMembers() public {
        uint256 id = _createPolicy(0);
        _addMember(id, carol);
        vm.prank(alice);
        registry.setActionRule{value: UPDATE_FEE}(id, ACTION, IPolicyRegistry.ActionRule.NOBODY);
        assertFalse(registry.isAllowed(id, carol, ACTION));
    }

    function test_isAllowed_ruleIsPerAction() public {
        uint256 id = _createPolicy(0);
        _addMember(id, carol);
        vm.prank(alice);
        registry.setActionRule{value: UPDATE_FEE}(id, ACTION, IPolicyRegistry.ActionRule.NOBODY);
        assertFalse(registry.isAllowed(id, carol, ACTION));
        assertTrue(registry.isAllowed(id, carol, keccak256("other-action")));
    }

    function test_isAllowed_falseWhenExpired() public {
        vm.prank(alice);
        uint256 id = registry.createPolicy{value: CREATION_FEE}(FLAG_OPEN_MEMBERSHIP, uint64(block.timestamp + 1 days), "", bytes32(0));
        assertTrue(registry.isAllowed(id, carol, ACTION));
        vm.warp(block.timestamp + 1 days + 1);
        assertFalse(registry.isAllowed(id, carol, ACTION));
        assertFalse(registry.isPolicyActive(id));
    }

    function test_isAllowed_falseForNonexistentPolicy() public view {
        assertFalse(registry.isAllowed(42, carol, ACTION));
    }

    function test_isAllowed_actionRulePrecedenceOverOpenMembership() public {
        uint256 id = _createPolicy(FLAG_OPEN_MEMBERSHIP);
        // open membership: everyone allowed by default
        assertTrue(registry.isAllowed(id, mallory, ACTION));
        // NOBODY rule overrides open membership for that action
        vm.prank(alice);
        registry.setActionRule{value: UPDATE_FEE}(id, ACTION, IPolicyRegistry.ActionRule.NOBODY);
        assertFalse(registry.isAllowed(id, mallory, ACTION));
        // ANYONE rule is equivalent to open membership for that action
        vm.prank(alice);
        registry.setActionRule{value: UPDATE_FEE}(id, ACTION, IPolicyRegistry.ActionRule.ANYONE);
        assertTrue(registry.isAllowed(id, mallory, ACTION));
        // a different action still follows open membership
        assertTrue(registry.isAllowed(id, mallory, keccak256("other")));
    }

    function testFuzz_isAllowed_onlyMembersWhenNoRule(address subject) public {
        uint256 id = _createPolicy(0);
        _addMember(id, carol);
        assertEq(registry.isAllowed(id, subject, ACTION), subject == carol);
    }

    // -- membership ---------------------------------------------------------

    function test_addMembers_batchAndCount() public {
        uint256 id = _createPolicy(0);
        address[] memory members = new address[](3);
        members[0] = carol;
        members[1] = bob;
        members[2] = carol; // duplicate must not double-count
        vm.prank(alice);
        registry.addMembers{value: UPDATE_FEE}(id, members);
        assertEq(registry.memberCount(id), 2);
        assertTrue(registry.isMember(id, carol));
        assertTrue(registry.isMember(id, bob));
    }

    function test_removeMembers_revokesInstantly() public {
        uint256 id = _createPolicy(0);
        _addMember(id, carol);
        address[] memory members = new address[](1);
        members[0] = carol;
        vm.prank(alice);
        registry.removeMembers{value: UPDATE_FEE}(id, members);
        assertFalse(registry.isMember(id, carol));
        assertFalse(registry.isAllowed(id, carol, ACTION));
        assertEq(registry.memberCount(id), 0);
    }

    function test_addMembers_rejectsZeroAddress() public {
        uint256 id = _createPolicy(0);
        address[] memory members = new address[](1);
        members[0] = address(0);
        vm.expectRevert(IPolicyRegistry.ZeroAddress.selector);
        vm.prank(alice);
        registry.addMembers{value: UPDATE_FEE}(id, members);
    }

    function test_addMembers_onlyOwnerOrAdmin() public {
        uint256 id = _createPolicy(0);
        address[] memory members = new address[](1);
        members[0] = mallory;
        vm.expectRevert(abi.encodeWithSelector(IPolicyRegistry.NotPolicyOwnerOrAdmin.selector, id, mallory));
        vm.prank(mallory);
        registry.addMembers{value: UPDATE_FEE}(id, members);
    }

    function test_adminCanManageMembersButNotAdmins() public {
        uint256 id = _createPolicy(0);
        vm.prank(alice);
        registry.addAdmin{value: UPDATE_FEE}(id, bob);
        assertTrue(registry.isAdmin(id, bob));

        address[] memory members = new address[](1);
        members[0] = carol;
        vm.prank(bob);
        registry.addMembers{value: UPDATE_FEE}(id, members);
        assertTrue(registry.isMember(id, carol));

        vm.expectRevert(abi.encodeWithSelector(IPolicyRegistry.NotPolicyOwner.selector, id, bob));
        vm.prank(bob);
        registry.addAdmin{value: UPDATE_FEE}(id, carol);
    }

    // -- issuers --------------------------------------------------------------

    function test_issuerLifecycle() public {
        uint256 id = _createPolicy(0);
        assertFalse(registry.isAuthorizedIssuer(id, bob));
        vm.prank(alice);
        registry.addIssuer{value: UPDATE_FEE}(id, bob);
        assertTrue(registry.isAuthorizedIssuer(id, bob));
        vm.prank(alice);
        registry.removeIssuer{value: UPDATE_FEE}(id, bob);
        assertFalse(registry.isAuthorizedIssuer(id, bob));
    }

    // -- conditions -------------------------------------------------------------

    function test_conditionSetAndClear() public {
        uint256 id = _createPolicy(0);
        bytes32 key = keccak256("maxDailySpend");
        vm.prank(alice);
        registry.setCondition{value: UPDATE_FEE}(id, key, abi.encode(uint256(5 ether)));
        assertEq(abi.decode(registry.getCondition(id, key), (uint256)), 5 ether);
        vm.prank(alice);
        registry.clearCondition{value: UPDATE_FEE}(id, key);
        assertEq(registry.getCondition(id, key).length, 0);
    }

    // -- lock ------------------------------------------------------------------

    function test_lockFreezesAllWritesButKeepsEnforcement() public {
        uint256 id = _createPolicy(0);
        _addMember(id, carol);
        vm.prank(alice);
        registry.lockPolicy(id);

        // still enforceable
        assertTrue(registry.isPolicyActive(id));
        assertTrue(registry.isAllowed(id, carol, ACTION));

        // every write path rejects
        address[] memory members = new address[](1);
        members[0] = mallory;
        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(IPolicyRegistry.PolicyIsLocked.selector, id));
        registry.addMembers{value: UPDATE_FEE}(id, members);
        vm.expectRevert(abi.encodeWithSelector(IPolicyRegistry.PolicyIsLocked.selector, id));
        registry.setActionRule{value: UPDATE_FEE}(id, ACTION, IPolicyRegistry.ActionRule.ANYONE);
        vm.expectRevert(abi.encodeWithSelector(IPolicyRegistry.PolicyIsLocked.selector, id));
        registry.setExpiry{value: UPDATE_FEE}(id, 0);
        vm.expectRevert(abi.encodeWithSelector(IPolicyRegistry.PolicyIsLocked.selector, id));
        registry.lockPolicy(id);
        vm.stopPrank();
    }

    function test_lock_onlyOwner() public {
        uint256 id = _createPolicy(0);
        vm.expectRevert(abi.encodeWithSelector(IPolicyRegistry.NotPolicyOwner.selector, id, bob));
        vm.prank(bob);
        registry.lockPolicy(id);
    }

    // -- ownership transfer -------------------------------------------------------

    function test_transferRequiresFlag() public {
        uint256 id = _createPolicy(0);
        vm.expectRevert(abi.encodeWithSelector(IPolicyRegistry.PolicyNotTransferable.selector, id));
        vm.prank(alice);
        registry.transferPolicyOwnership(id, bob);
    }

    function test_transferWithFlag() public {
        uint256 id = _createPolicy(FLAG_TRANSFERABLE);
        vm.prank(alice);
        registry.transferPolicyOwnership(id, bob);
        assertTrue(registry.isOwner(id, bob));
        assertFalse(registry.isOwner(id, alice));
    }

    function test_transferRejectsZeroAddress() public {
        uint256 id = _createPolicy(FLAG_TRANSFERABLE);
        vm.expectRevert(IPolicyRegistry.ZeroAddress.selector);
        vm.prank(alice);
        registry.transferPolicyOwnership(id, address(0));
    }

    // -- fees ----------------------------------------------------------------------

    function test_writesRequireExactUpdateFee() public {
        uint256 id = _createPolicy(0);
        address[] memory members = new address[](1);
        members[0] = carol;
        vm.expectRevert(abi.encodeWithSelector(IPolicyRegistry.WrongFee.selector, UPDATE_FEE, 0));
        vm.prank(alice);
        registry.addMembers(id, members);
    }

    function test_withdrawFees_goesToCollector() public {
        _createPolicy(0);
        uint256 id = 1;
        _addMember(id, carol);
        uint256 expected = CREATION_FEE + UPDATE_FEE;
        assertEq(address(registry).balance, expected);
        registry.withdrawFees(); // anyone may trigger; destination is fixed
        assertEq(collector.balance, expected);
        assertEq(address(registry).balance, 0);
    }

    function test_setFeeCollector_updatesAndRoutesWithdrawal() public {
        address newCollector = makeAddr("newCollector");
        vm.expectEmit(true, false, false, false);
        emit PolicyRegistry.FeeCollectorUpdated(newCollector);
        vm.prank(protocolOwner);
        registry.setFeeCollector(newCollector);

        _createPolicy(0); // accrue the creation fee
        registry.withdrawFees();
        assertEq(newCollector.balance, CREATION_FEE);
        assertEq(collector.balance, 0); // old collector gets nothing
    }

    function test_setFeeCollector_rejectsZero() public {
        vm.expectRevert(IPolicyRegistry.ZeroAddress.selector);
        vm.prank(protocolOwner);
        registry.setFeeCollector(address(0));
    }

    function test_setFeeCollector_onlyProtocolOwner() public {
        vm.expectRevert();
        vm.prank(mallory);
        registry.setFeeCollector(mallory);
    }

    function test_withdrawFees_revertingCollectorSurfacesAndRecovers() public {
        RejectEther bad = new RejectEther();
        vm.prank(protocolOwner);
        registry.setFeeCollector(address(bad));
        _createPolicy(0); // accrue a fee

        vm.expectRevert(PolicyRegistry.FeeTransferFailed.selector);
        registry.withdrawFees(); // funds are NOT lost, just not withdrawable yet

        // re-point to a payable EOA and the funds drain — proving recoverability
        vm.prank(protocolOwner);
        registry.setFeeCollector(collector);
        registry.withdrawFees();
        assertEq(collector.balance, CREATION_FEE);
    }

    function test_setFees_cappedByImmutables() public {
        vm.prank(protocolOwner);
        registry.setFees(MAX_CREATION_FEE, MAX_UPDATE_FEE); // at cap: fine
        vm.expectRevert(
            abi.encodeWithSelector(PolicyRegistry.FeeAboveCap.selector, MAX_CREATION_FEE + 1, MAX_CREATION_FEE)
        );
        vm.prank(protocolOwner);
        registry.setFees(MAX_CREATION_FEE + 1, UPDATE_FEE);
    }

    function test_setFees_onlyProtocolOwner() public {
        vm.expectRevert();
        vm.prank(mallory);
        registry.setFees(0, 0);
    }

    function test_constructor_rejectsFeesAboveCaps() public {
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.FeeAboveCap.selector, 2, 1));
        new PolicyRegistry(protocolOwner, collector, 2, 0, 1, 1);
    }

    function test_protocolOwnerCannotTouchPolicyData() public {
        uint256 id = _createPolicy(0);
        address[] memory members = new address[](1);
        members[0] = mallory;
        vm.deal(protocolOwner, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(IPolicyRegistry.NotPolicyOwnerOrAdmin.selector, id, protocolOwner));
        vm.prank(protocolOwner);
        registry.addMembers{value: UPDATE_FEE}(id, members);
    }
}
