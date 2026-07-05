// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IGrantVerifier} from "./interfaces/IGrantVerifier.sol";
import {IPolicyRegistry} from "./interfaces/IPolicyRegistry.sol";

/// @title GrantVerifier
/// @notice Verifies and consumes EIP-712 authorization grants signed by
///         issuers that policy owners authorized in the PolicyRegistry.
///         Stateless except for per-issuer nonce consumption. Immutable.
contract GrantVerifier is IGrantVerifier, EIP712 {
    bytes32 private constant GRANT_TYPEHASH = keccak256(
        "Grant(uint256 policyId,address subject,bytes32 action,uint64 issuedAt,uint64 expiresAt,uint256 nonce,address issuer,address target)"
    );

    /// @inheritdoc IGrantVerifier
    address public immutable registry;

    /// @dev issuer => nonce => consumed. Namespacing by issuer means no issuer
    ///      can exhaust or front-run another issuer's nonce space.
    mapping(address => mapping(uint256 => bool)) private _usedNonces;

    constructor(address registry_) EIP712("SmartPolicy Grants", "1") {
        require(registry_ != address(0), "registry is zero");
        registry = registry_;
    }

    /// @inheritdoc IGrantVerifier
    function isGrantValid(Grant calldata grant, bytes calldata signature) external view returns (bool) {
        return _check(grant, signature) == bytes4(0);
    }

    /// @inheritdoc IGrantVerifier
    function consumeGrant(Grant calldata grant, bytes calldata signature) external {
        // Only the bound target may consume — stops a front-runner from reading
        // a broadcast grant out of the mempool and burning its nonce (DoS).
        if (msg.sender != grant.target) revert GrantTargetMismatch();
        bytes4 err = _check(grant, signature);
        if (err != bytes4(0)) {
            assembly {
                mstore(0, err)
                revert(0, 4)
            }
        }
        _usedNonces[grant.issuer][grant.nonce] = true;
        emit GrantConsumed(grant.policyId, grant.subject, grant.action, grant.issuer, grant.nonce);
    }

    /// @inheritdoc IGrantVerifier
    function hashGrant(Grant calldata grant) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    GRANT_TYPEHASH,
                    grant.policyId,
                    grant.subject,
                    grant.action,
                    grant.issuedAt,
                    grant.expiresAt,
                    grant.nonce,
                    grant.issuer,
                    grant.target
                )
            )
        );
    }

    /// @inheritdoc IGrantVerifier
    function isNonceUsed(address issuer, uint256 nonce) external view returns (bool) {
        return _usedNonces[issuer][nonce];
    }

    /// @dev Runs every check and returns the selector of the violated error,
    ///      or bytes4(0) when the grant is valid. Shared by the boolean view
    ///      and the consuming path so they can never disagree.
    function _check(Grant calldata grant, bytes calldata signature) internal view returns (bytes4) {
        if (block.timestamp < grant.issuedAt) return GrantNotYetValid.selector;
        if (block.timestamp > grant.expiresAt) return GrantExpired.selector;
        if (_usedNonces[grant.issuer][grant.nonce]) return GrantNonceUsed.selector;
        if (!IPolicyRegistry(registry).isPolicyActive(grant.policyId)) return GrantPolicyInactive.selector;
        if (!IPolicyRegistry(registry).isAuthorizedIssuer(grant.policyId, grant.issuer)) {
            return GrantIssuerNotAuthorized.selector;
        }
        (address signer, ECDSA.RecoverError recoverError,) = ECDSA.tryRecover(hashGrant(grant), signature);
        if (recoverError != ECDSA.RecoverError.NoError || signer != grant.issuer) {
            return GrantSignatureInvalid.selector;
        }
        return bytes4(0);
    }
}
