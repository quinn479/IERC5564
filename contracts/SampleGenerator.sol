pragma solidity >=0.8.0;
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "./interfaces/IERC5564Generator.sol";
import "./libs/EllipticCurve.sol";
import "./libs/BytesLib.sol";
import "./interfaces/IERC5564Registry.sol";
import "hardhat/console.sol";

/// @notice Sample IERC5564Generator implementation for the secp256k1 curve.
contract SampleGenerator is
    EllipticCurve,
    Initializable,
    BytesLib,
    IERC5564Generator
{
    IERC5564Registry public REGISTRY;

    function initialize(address _registry) external initializer {
        REGISTRY = IERC5564Registry(_registry);
    }

    /// @notice Sample implementation for parsing stealth keys on the secp256k1 curve.
    function stealthKeys(
        address registrant
    )
        public
        view
        override
        returns (
            uint256 spendingPubKeyX,
            uint256 spendingPubKeyY,
            uint256 viewingPubKeyX,
            uint256 viewingPubKeyY
        )
    {
        // Fetch the raw spending and viewing keys from the registry.
        (bytes memory spendingPubKey, bytes memory viewingPubKey) = REGISTRY
            .stealthKeys(registrant, address(this));

        // Parse the keys.
        assembly {
            spendingPubKeyX := mload(add(spendingPubKey, 0x20))
            spendingPubKeyY := mload(add(spendingPubKey, 0x40))
            viewingPubKeyX := mload(add(viewingPubKey, 0x20))
            viewingPubKeyY := mload(add(viewingPubKey, 0x40))
        }
    }

    /// @notice Sample implementation for generating stealth addresses for the secp256k1 curve.
    function generateStealthAddress(
        address registrant,
        bytes memory ephemeralPrivKey
    )
        external
        view
        override
        returns (
            address stealthAddress,
            bytes memory ephemeralPubKey,
            bytes memory sharedSecret,
            bytes32 viewTag
        )
    {
        // Get the ephemeral public key from the private key.
        {
            (uint256 x1, uint256 y1) = multiplyScalar(
                gx,
                gy,
                BytesLib.toUint256(ephemeralPrivKey, 0)
            );
            ephemeralPubKey = BytesLib.concat(
                BytesLib.toBytes(bytes32(x1)),
                BytesLib.toBytes(bytes32(y1))
            );
        }
        // Get user's parsed public keys.
        (
            uint256 spendingPubKeyX,
            uint256 spendingPubKeyY,
            uint256 viewingPubKeyX,
            uint256 viewingPubKeyY
        ) = stealthKeys(registrant);

        {
            // Generate shared secret from sender's private key and recipient's viewing key.
            (uint256 x1, uint256 y1) = multiplyScalar(
                viewingPubKeyX,
                viewingPubKeyY,
                BytesLib.toUint256(ephemeralPrivKey, 0)
            );
            sharedSecret = BytesLib.concat(
                BytesLib.toBytes(bytes32(x1)),
                BytesLib.toBytes(bytes32(y1))
            );
        }
        bytes32 sharedSecretHash = keccak256(sharedSecret);
        // bytes32 sharedSecretHash1 = sharedSecretHash;

        // Generate a point from the hash of the shared secret
        bytes memory sharedSecretPoint;
        {
            // Generate shared secret from sender's private key and recipient's viewing key.
            (uint256 x1, uint256 y1) = multiplyScalar(
                gx,
                gy,
                BytesLib.toUint256(BytesLib.toBytes(sharedSecretHash), 0)
            );
            sharedSecretPoint = BytesLib.concat(
                BytesLib.toBytes(bytes32(x1)),
                BytesLib.toBytes(bytes32(y1))
            );
        }

        (uint256 ax, uint256 ay) = decomposeKey(sharedSecretPoint);
        // Generate sender's public key from their ephemeral private key.
        // (ax, ay) = add(spendingPubKeyX, spendingPubKeyY, ax, ay);
        (ax, ay) = ecAdd(spendingPubKeyX, spendingPubKeyY, ax, ay, aa, pp);

        bytes memory stealthPubKey = BytesLib.concat(
            BytesLib.toBytes(bytes32(ax)),
            BytesLib.toBytes(bytes32(ay))
        );

        // Compute stealth address from the stealth public key.
        // get last 20 bytes
        stealthAddress = pubkeyToAddress_fix(stealthPubKey);
        // Generate view tag for enabling faster parsing for the recipient
        viewTag = BytesLib.toBytes32(
            BytesLib.concat(
                abi.encodePacked(stealthAddress),
                BytesLib.slice(BytesLib.toBytes(sharedSecretHash), 0, 12)
            ),
            0
        );
    }

    function pubkeyToAddress(
        bytes memory pub
    ) public pure returns (address addr) {
        bytes32 hash = keccak256(pub);
        assembly {
            mstore(0, hash)
            addr := mload(0xC)
        }
    }

    // last 20 bytes
    function pubkeyToAddress_fix(
        bytes memory pub
    ) public pure returns (address addr) {
        bytes32 hash = keccak256(pub);
        bytes20 res3;
        assembly {
            res3 := shl(96, hash)
        }

        address wallet = address(uint160(res3));
        return wallet;
    }
}
