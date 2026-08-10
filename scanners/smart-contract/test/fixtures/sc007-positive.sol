// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Positive fixture for SC007: anyone can mint.
contract MintPositive {
    mapping(address => uint256) public balances;

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }
}
