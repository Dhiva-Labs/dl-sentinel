// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Positive fixture for SC006: proxy-pattern initializer with no guard.
contract InitializerPositive {
    address public owner;
    bool public initialized;

    function initialize(address newOwner) external {
        owner = newOwner;
        initialized = true;
    }
}
