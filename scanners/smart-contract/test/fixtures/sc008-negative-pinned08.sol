// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Negative fixture for SC008: same raw arithmetic shape as the positive
// fixture, but the pragma is pinned to 0.8.19 (built-in overflow checks),
// so this must not trigger.
contract UncheckedArithmeticPinned08Negative {
    uint256 public totalSupply;

    function increase(uint256 amount) external {
        totalSupply = totalSupply + amount;
    }
}
