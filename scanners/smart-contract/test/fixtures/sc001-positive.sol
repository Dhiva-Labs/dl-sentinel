// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Positive fixture for SC001: external call before the state write.
contract ReentrancyPositive {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }
}
