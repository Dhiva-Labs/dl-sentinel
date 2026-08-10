// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

// Positive fixture for SC008: pre-0.8 pragma, raw arithmetic on state, no SafeMath.
contract UncheckedArithmeticPositive {
    uint256 public totalSupply;

    function increase(uint256 amount) external {
        totalSupply = totalSupply + amount;
    }
}
