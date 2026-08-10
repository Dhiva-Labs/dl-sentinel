// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

// Positive fixture for SC011: a grab bag of deprecated constructs.
contract DeprecatedPositive {
    function legacyHash(bytes memory data) public pure returns (bytes32) {
        return sha3(data);
    }

    function legacyVar() public pure returns (uint256) {
        var x = 1;
        return x;
    }

    function legacyThrow(uint256 value) public pure {
        if (value == 0) {
            throw;
        }
    }

    function legacyDestroy() public {
        suicide(msg.sender);
    }

    function legacyCallcode(address target, bytes memory data) public {
        target.callcode(data);
    }
}
