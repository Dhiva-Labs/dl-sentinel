// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Negative fixture for SC001: checks-effects-interactions — the state write
// happens BEFORE the external call, so this must not trigger.
contract ReentrancyNegative {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
