// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Negative fixture for SC010: block.timestamp is recorded as a plain
// bookkeeping value — no modulo, no random/lottery/winner/seed naming
// anywhere in the function or on the line.
contract RandomnessNegative {
    uint256 public lastUpdated;

    function touch() external {
        lastUpdated = block.timestamp;
    }
}
