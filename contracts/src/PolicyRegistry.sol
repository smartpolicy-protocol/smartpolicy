// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IPolicyRegistry, FLAG_OPEN_MEMBERSHIP, FLAG_TRANSFERABLE} from "./interfaces/IPolicyRegistry.sol";

/// @title PolicyRegistry
/// @notice Immutable single source of truth for policies. See IPolicyRegistry
///         for the model. There is no proxy and no upgrade path.
/// @dev The Ownable owner is the *protocol* owner whose only powers are fee
///      parameters (hard-capped by immutables set at deploy) and the fee
///      collector address. Policy data is exclusively governed by each
///      policy's own owner/admins.
contract PolicyRegistry is IPolicyRegistry, Ownable2Step {
    // ---------------------------------------------------------------------
    // Protocol fee state
    // ---------------------------------------------------------------------

    /// @notice Hard ceilings the protocol owner can never raise fees above.
    uint256 public immutable maxCreationFee;
    uint256 public immutable maxUpdateFee;

    uint256 public creationFee;
    uint256 public updateFee;
    address public feeCollector;

    error FeeAboveCap(uint256 fee, uint256 cap);
    error FeeTransferFailed();

    event FeesUpdated(uint256 creationFee, uint256 updateFee);
    event FeeCollectorUpdated(address indexed collector);
    event FeesWithdrawn(address indexed collector, uint256 amount);

    // ---------------------------------------------------------------------
    // Policy state
    // ---------------------------------------------------------------------

    uint256 private _policyCount;
    mapping(uint256 => Policy) private _policies;
    mapping(uint256 => mapping(address => bool)) private _members;
    mapping(uint256 => uint256) private _memberCounts;
    mapping(uint256 => mapping(address => bool)) private _admins;
    mapping(uint256 => mapping(address => bool)) private _issuers;
    mapping(uint256 => mapping(bytes32 => ActionRule)) private _actionRules;
    mapping(uint256 => mapping(bytes32 => bytes)) private _conditions;

    // ---------------------------------------------------------------------
    // Construction
    // ---------------------------------------------------------------------

    constructor(
        address protocolOwner,
        address feeCollector_,
        uint256 creationFee_,
        uint256 updateFee_,
        uint256 maxCreationFee_,
        uint256 maxUpdateFee_
    ) Ownable(protocolOwner) {
        if (feeCollector_ == address(0)) revert ZeroAddress();
        if (creationFee_ > maxCreationFee_) revert FeeAboveCap(creationFee_, maxCreationFee_);
        if (updateFee_ > maxUpdateFee_) revert FeeAboveCap(updateFee_, maxUpdateFee_);
        maxCreationFee = maxCreationFee_;
        maxUpdateFee = maxUpdateFee_;
        creationFee = creationFee_;
        updateFee = updateFee_;
        feeCollector = feeCollector_;
    }

    // ---------------------------------------------------------------------
    // Modifiers
    // ---------------------------------------------------------------------

    modifier exists(uint256 policyId) {
        if (_policies[policyId].owner == address(0)) revert PolicyNotFound(policyId);
        _;
    }

    modifier notLocked(uint256 policyId) {
        if (_policies[policyId].locked) revert PolicyIsLocked(policyId);
        _;
    }

    modifier onlyPolicyOwner(uint256 policyId) {
        if (_policies[policyId].owner != msg.sender) revert NotPolicyOwner(policyId, msg.sender);
        _;
    }

    modifier onlyPolicyOwnerOrAdmin(uint256 policyId) {
        if (_policies[policyId].owner != msg.sender && !_admins[policyId][msg.sender]) {
            revert NotPolicyOwnerOrAdmin(policyId, msg.sender);
        }
        _;
    }

    modifier paysUpdateFee() {
        if (msg.value != updateFee) revert WrongFee(updateFee, msg.value);
        _;
    }

    // ---------------------------------------------------------------------
    // Writes — policy lifecycle
    // ---------------------------------------------------------------------

    /// @inheritdoc IPolicyRegistry
    function createPolicy(uint8 flags, uint64 expiresAt, string calldata metadataURI, bytes32 metadataHash)
        external
        payable
        returns (uint256 policyId)
    {
        if (msg.value != creationFee) revert WrongFee(creationFee, msg.value);
        policyId = ++_policyCount;
        _policies[policyId] = Policy({
            owner: msg.sender,
            expiresAt: expiresAt,
            flags: flags,
            locked: false,
            metadataHash: metadataHash,
            metadataURI: metadataURI
        });
        emit PolicyCreated(policyId, msg.sender, flags, expiresAt);
        if (bytes(metadataURI).length > 0 || metadataHash != bytes32(0)) {
            emit PolicyMetadataUpdated(policyId, metadataURI, metadataHash);
        }
    }

    /// @inheritdoc IPolicyRegistry
    function lockPolicy(uint256 policyId) external exists(policyId) onlyPolicyOwner(policyId) notLocked(policyId) {
        _policies[policyId].locked = true;
        emit PolicyLocked(policyId);
    }

    /// @inheritdoc IPolicyRegistry
    function transferPolicyOwnership(uint256 policyId, address newOwner)
        external
        exists(policyId)
        onlyPolicyOwner(policyId)
        notLocked(policyId)
    {
        if (newOwner == address(0)) revert ZeroAddress();
        if (_policies[policyId].flags & FLAG_TRANSFERABLE == 0) revert PolicyNotTransferable(policyId);
        address previousOwner = _policies[policyId].owner;
        _policies[policyId].owner = newOwner;
        emit PolicyOwnershipTransferred(policyId, previousOwner, newOwner);
    }

    /// @inheritdoc IPolicyRegistry
    function addAdmin(uint256 policyId, address admin)
        external
        payable
        exists(policyId)
        onlyPolicyOwner(policyId)
        notLocked(policyId)
        paysUpdateFee
    {
        if (admin == address(0)) revert ZeroAddress();
        if (!_admins[policyId][admin]) {
            _admins[policyId][admin] = true;
            emit AdminAdded(policyId, admin);
        }
    }

    /// @inheritdoc IPolicyRegistry
    function removeAdmin(uint256 policyId, address admin)
        external
        payable
        exists(policyId)
        onlyPolicyOwner(policyId)
        notLocked(policyId)
        paysUpdateFee
    {
        if (_admins[policyId][admin]) {
            _admins[policyId][admin] = false;
            emit AdminRemoved(policyId, admin);
        }
    }

    // ---------------------------------------------------------------------
    // Writes — rules (owner or admin)
    // ---------------------------------------------------------------------

    /// @inheritdoc IPolicyRegistry
    function addMembers(uint256 policyId, address[] calldata members)
        external
        payable
        exists(policyId)
        onlyPolicyOwnerOrAdmin(policyId)
        notLocked(policyId)
        paysUpdateFee
    {
        for (uint256 i = 0; i < members.length; i++) {
            address member = members[i];
            if (member == address(0)) revert ZeroAddress();
            if (!_members[policyId][member]) {
                _members[policyId][member] = true;
                _memberCounts[policyId]++;
                emit MemberAdded(policyId, member);
            }
        }
    }

    /// @inheritdoc IPolicyRegistry
    function removeMembers(uint256 policyId, address[] calldata members)
        external
        payable
        exists(policyId)
        onlyPolicyOwnerOrAdmin(policyId)
        notLocked(policyId)
        paysUpdateFee
    {
        for (uint256 i = 0; i < members.length; i++) {
            address member = members[i];
            if (_members[policyId][member]) {
                _members[policyId][member] = false;
                _memberCounts[policyId]--;
                emit MemberRemoved(policyId, member);
            }
        }
    }

    /// @inheritdoc IPolicyRegistry
    function setActionRule(uint256 policyId, bytes32 action, ActionRule rule)
        external
        payable
        exists(policyId)
        onlyPolicyOwnerOrAdmin(policyId)
        notLocked(policyId)
        paysUpdateFee
    {
        _actionRules[policyId][action] = rule;
        emit ActionRuleSet(policyId, action, rule);
    }

    /// @inheritdoc IPolicyRegistry
    function addIssuer(uint256 policyId, address issuer)
        external
        payable
        exists(policyId)
        onlyPolicyOwnerOrAdmin(policyId)
        notLocked(policyId)
        paysUpdateFee
    {
        if (issuer == address(0)) revert ZeroAddress();
        if (!_issuers[policyId][issuer]) {
            _issuers[policyId][issuer] = true;
            emit IssuerAdded(policyId, issuer);
        }
    }

    /// @inheritdoc IPolicyRegistry
    function removeIssuer(uint256 policyId, address issuer)
        external
        payable
        exists(policyId)
        onlyPolicyOwnerOrAdmin(policyId)
        notLocked(policyId)
        paysUpdateFee
    {
        if (_issuers[policyId][issuer]) {
            _issuers[policyId][issuer] = false;
            emit IssuerRemoved(policyId, issuer);
        }
    }

    /// @inheritdoc IPolicyRegistry
    function setCondition(uint256 policyId, bytes32 key, bytes calldata value)
        external
        payable
        exists(policyId)
        onlyPolicyOwnerOrAdmin(policyId)
        notLocked(policyId)
        paysUpdateFee
    {
        _conditions[policyId][key] = value;
        emit ConditionSet(policyId, key, value);
    }

    /// @inheritdoc IPolicyRegistry
    function clearCondition(uint256 policyId, bytes32 key)
        external
        payable
        exists(policyId)
        onlyPolicyOwnerOrAdmin(policyId)
        notLocked(policyId)
        paysUpdateFee
    {
        delete _conditions[policyId][key];
        emit ConditionCleared(policyId, key);
    }

    /// @inheritdoc IPolicyRegistry
    function setExpiry(uint256 policyId, uint64 expiresAt)
        external
        payable
        exists(policyId)
        onlyPolicyOwnerOrAdmin(policyId)
        notLocked(policyId)
        paysUpdateFee
    {
        _policies[policyId].expiresAt = expiresAt;
        emit PolicyExpiryUpdated(policyId, expiresAt);
    }

    /// @inheritdoc IPolicyRegistry
    function setMetadataURI(uint256 policyId, string calldata metadataURI, bytes32 metadataHash)
        external
        payable
        exists(policyId)
        onlyPolicyOwnerOrAdmin(policyId)
        notLocked(policyId)
        paysUpdateFee
    {
        _policies[policyId].metadataURI = metadataURI;
        _policies[policyId].metadataHash = metadataHash;
        emit PolicyMetadataUpdated(policyId, metadataURI, metadataHash);
    }

    // ---------------------------------------------------------------------
    // Reads
    // ---------------------------------------------------------------------

    /// @inheritdoc IPolicyRegistry
    function isAllowed(uint256 policyId, address subject, bytes32 action) external view returns (bool) {
        if (!_isActive(policyId)) return false;
        ActionRule rule = _actionRules[policyId][action];
        if (rule == ActionRule.ANYONE) return true;
        if (rule == ActionRule.NOBODY) return false;
        return _isMember(policyId, subject); // UNSET and MEMBERS
    }

    /// @inheritdoc IPolicyRegistry
    function isPolicyActive(uint256 policyId) external view returns (bool) {
        return _isActive(policyId);
    }

    /// @inheritdoc IPolicyRegistry
    function isMember(uint256 policyId, address account) external view returns (bool) {
        return _isMember(policyId, account);
    }

    /// @inheritdoc IPolicyRegistry
    function isAdmin(uint256 policyId, address account) external view returns (bool) {
        return _admins[policyId][account];
    }

    /// @inheritdoc IPolicyRegistry
    function isOwner(uint256 policyId, address account) external view returns (bool) {
        return _policies[policyId].owner == account && account != address(0);
    }

    /// @inheritdoc IPolicyRegistry
    function isAuthorizedIssuer(uint256 policyId, address issuer) external view returns (bool) {
        return _issuers[policyId][issuer];
    }

    /// @inheritdoc IPolicyRegistry
    function getPolicy(uint256 policyId) external view exists(policyId) returns (Policy memory) {
        return _policies[policyId];
    }

    /// @inheritdoc IPolicyRegistry
    function getActionRule(uint256 policyId, bytes32 action) external view returns (ActionRule) {
        return _actionRules[policyId][action];
    }

    /// @inheritdoc IPolicyRegistry
    function getCondition(uint256 policyId, bytes32 key) external view returns (bytes memory) {
        return _conditions[policyId][key];
    }

    /// @inheritdoc IPolicyRegistry
    function memberCount(uint256 policyId) external view returns (uint256) {
        return _memberCounts[policyId];
    }

    /// @inheritdoc IPolicyRegistry
    function policyCount() external view returns (uint256) {
        return _policyCount;
    }

    function _isActive(uint256 policyId) internal view returns (bool) {
        Policy storage p = _policies[policyId];
        if (p.owner == address(0)) return false;
        return p.expiresAt == 0 || p.expiresAt >= block.timestamp;
    }

    function _isMember(uint256 policyId, address account) internal view returns (bool) {
        if (_policies[policyId].flags & FLAG_OPEN_MEMBERSHIP != 0) return true;
        return _members[policyId][account];
    }

    // ---------------------------------------------------------------------
    // Protocol fee administration (the protocol owner's ONLY powers)
    // ---------------------------------------------------------------------

    function setFees(uint256 creationFee_, uint256 updateFee_) external onlyOwner {
        if (creationFee_ > maxCreationFee) revert FeeAboveCap(creationFee_, maxCreationFee);
        if (updateFee_ > maxUpdateFee) revert FeeAboveCap(updateFee_, maxUpdateFee);
        creationFee = creationFee_;
        updateFee = updateFee_;
        emit FeesUpdated(creationFee_, updateFee_);
    }

    function setFeeCollector(address collector) external onlyOwner {
        if (collector == address(0)) revert ZeroAddress();
        feeCollector = collector;
        emit FeeCollectorUpdated(collector);
    }

    /// @notice Push accumulated fees to the collector. Callable by anyone:
    ///         the destination is fixed, so there is nothing to abuse.
    function withdrawFees() external {
        uint256 amount = address(this).balance;
        address collector = feeCollector;
        (bool ok,) = collector.call{value: amount}("");
        if (!ok) revert FeeTransferFailed();
        emit FeesWithdrawn(collector, amount);
    }
}
