// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Negative fixture for SC007: minting restricted to the owner.
contract MintNegative {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
    }
}
