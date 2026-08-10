// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "overflow");
        return c;
    }
}

// Negative fixture for SC008: same pre-0.8 pragma, but arithmetic goes
// through SafeMath, so this must not trigger.
contract UncheckedArithmeticSafeMathNegative {
    using SafeMath for uint256;
    uint256 public totalSupply;

    function increase(uint256 amount) external {
        totalSupply = totalSupply.add(amount);
    }
}
