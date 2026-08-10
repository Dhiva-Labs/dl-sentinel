// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract Truncated {
    uint256 public value;

    function setValue(uint256 v) external {
        value = v;
    }

    function broken(uint256 x) external {
        value = x;
        if (x > 0) {
