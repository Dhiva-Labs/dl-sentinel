// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Negative fixture for SC017: a single delegatecall outside any loop, and a
// loop that contains no delegatecall at all.
contract NoDelegatecallLoop {
    address public immutable implementation;
    uint256 public total;

    constructor(address impl) {
        implementation = impl;
    }

    function callOnce(bytes calldata data) external payable {
        (bool ok, ) = implementation.delegatecall(data);
        require(ok, "call failed");
    }

    function sum(uint256[] calldata values) external {
        for (uint256 i = 0; i < values.length; i++) {
            total += values[i];
        }
    }
}
