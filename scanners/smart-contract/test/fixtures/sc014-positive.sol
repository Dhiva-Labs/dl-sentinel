// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Positive fixture for SC014, both shapes.

// The classic UUPS bug: the authorization hook exists (so the compiler is
// satisfied) but authorizes everyone.
contract UupsUnprotected {
    address public implementation;

    function _authorizeUpgrade(address newImplementation) internal {}

    function setImplementation(address newImplementation) internal {
        implementation = newImplementation;
    }
}

// A contract rolling its own upgrade entry point without guarding it.
contract ProxyUnprotected {
    address public implementation;

    function upgradeTo(address newImplementation) external {
        implementation = newImplementation;
    }
}
