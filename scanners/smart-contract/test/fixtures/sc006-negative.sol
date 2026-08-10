// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Negative fixture for SC006: initializer guarded by an onlyOwner modifier.
contract InitializerNegative {
    address public owner;
    bool public initialized;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function initialize(address newOwner) external onlyOwner {
        owner = newOwner;
        initialized = true;
    }
}
