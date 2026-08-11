// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Positive fixture for SC007 under modifier-body analysis: the modifier is
// named onlyOwner, which the old name-only heuristic accepted, but its body
// checks nothing. Anyone can still mint.
contract MintWithEmptyGuard {
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        _;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
    }
}
