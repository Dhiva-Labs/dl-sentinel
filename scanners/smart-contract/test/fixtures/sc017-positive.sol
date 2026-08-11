// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Positive fixture for SC017: a payable multicall that delegatecalls once per
// entry, so every iteration sees the same msg.value.
contract PayableMulticall {
    address public immutable implementation;

    constructor(address impl) {
        implementation = impl;
    }

    function multicall(bytes[] calldata data) external payable {
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, ) = implementation.delegatecall(data[i]);
            require(ok, "call failed");
        }
    }
}
