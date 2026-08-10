// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Negative fixture for SC003: the call result is captured and required, and
// a separate .transfer( call — which reverts on failure — is never flagged.
contract UncheckedCallNegative {
    function forward(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data);
        require(ok, "call failed");
    }

    function pay(address payable target, uint256 amount) external {
        target.transfer(amount);
    }
}
