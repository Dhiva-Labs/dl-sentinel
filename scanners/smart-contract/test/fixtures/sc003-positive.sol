// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Positive fixture for SC003: low-level call result is discarded.
contract UncheckedCallPositive {
    function forward(address target, bytes calldata data) external {
        target.call(data);
    }
}
