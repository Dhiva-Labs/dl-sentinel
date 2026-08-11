// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Negative fixture for SC014: the same two shapes, correctly guarded — the
// hook by a modifier whose body really does check the caller, the entry point
// by an inline msg.sender check.
contract UupsProtected {
    address public owner;
    address public implementation;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function _authorizeUpgrade(address newImplementation) internal onlyOwner {}

    function upgradeTo(address newImplementation) external {
        require(msg.sender == owner, "not owner");
        implementation = newImplementation;
    }
}
