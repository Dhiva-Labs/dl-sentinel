// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract UnbalancedBraces {
    uint256 public value;

    function setValue(uint256 v) external {
        value = v;
    }
}

}}} // stray extra closing braces
