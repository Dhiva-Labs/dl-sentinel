// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Positive fixture for SC005: selfdestruct callable by anyone.
contract SelfdestructPositive {
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}
