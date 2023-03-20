pragma solidity >=0.8.0;
import "./interfaces/IERC5564Messenger.sol";

/// @notice Sample IERC5564Generator implementation for the secp256k1 curve.
contract SampleMessenger is IERC5564Messenger {
    /// @dev Called by integrators to emit an `Announcement` event.
    /// @dev `ephemeralPubKey` represents the ephemeral public key used by the sender.
    /// @dev `stealthRecipientAndViewTag` contains the stealth address (20 bytes) and the view tag (12
    /// bytes).
    /// @dev `metadata` is an arbitrary field that the sender can use however they like, but the below
    /// guidelines are recommended:
    ///   - When sending ERC-20 tokens, the metadata SHOULD include the token address as the first 20
    ///     bytes, and the amount being sent as the following 32 bytes.
    ///   - When sending ERC-721 tokens, the metadata SHOULD include the token address as the first 20
    ///     bytes, and the token ID being sent as the following 32 bytes.
    function announce(
        bytes memory ephemeralPubKey,
        bytes32 stealthRecipientAndViewTag,
        bytes32 metadata
    ) public override {
        emit Announcement(ephemeralPubKey, stealthRecipientAndViewTag, metadata);
    }

    function privateETHTransfer(
        address payable _to, //  bytes
        bytes memory ephemeralPubKey, // 32 bytes
        bytes32 stealthRecipientAndViewTag,  // 20 bytes stealth address and 12 bytes ....
        bytes32 metadata // 20 bytes token_address and 12 bytes of amount
    ) external payable {
        (bool sent, ) = _to.call{value: msg.value}("");
        require(sent, "Failed to send Ether");
        announce(ephemeralPubKey, stealthRecipientAndViewTag, metadata);
    }
}
