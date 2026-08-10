// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Negative fixture for SC004: delegatecall target is an immutable address
// fixed at deployment, not derived from a parameter or mutable state.
contract DelegatecallNegative {
    address public immutable implementation;

    constructor(address impl) {
        implementation = impl;
    }

    function execute(bytes calldata data) external {
        (bool ok, ) = implementation.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}
