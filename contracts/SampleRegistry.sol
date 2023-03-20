pragma solidity >=0.8.0;
import "./interfaces/IERC5564Registry.sol";

/// @notice Sample IERC5564Generator implementation for the secp256k1 curve.
contract SampleRegistry is IERC5564Registry {
    mapping(address => mapping(address => bytes[2])) public stealthKeysRegistry;

    function stealthKeys(address registrant, address generator)
        external
        override
        view
        returns (bytes memory spendingPubKey, bytes memory viewingPubKey)
    {
        bytes[2] memory keys = stealthKeysRegistry[registrant][generator];
        return (keys[0], keys[1]);
    }

    /// @notice Sets the caller's stealth public keys for the `generator` contract.
    function registerKeys(
        address generator,
        bytes memory spendingPubKey,
        bytes memory viewingPubKey
    ) external override {
        stealthKeysRegistry[msg.sender][generator] = [spendingPubKey, viewingPubKey];
        emit StealthKeyChanged(msg.sender, generator, spendingPubKey, viewingPubKey);
    }

    /// @notice Sets the `registrant`s stealth public keys for the `generator` contract using their
    /// `signature`.
    /// @dev MUST support both EOA signatures and EIP-1271 signatures.
    function registerKeysOnBehalf(
        address registrant,
        address generator,
        bytes memory signature,
        bytes memory spendingPubKey,
        bytes memory viewingPubKey
    ) external override {
        // do nothing for now
    }
}
