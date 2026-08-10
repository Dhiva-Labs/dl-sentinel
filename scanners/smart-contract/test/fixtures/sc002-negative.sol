// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Negative fixture for SC002: msg.sender used instead of tx.origin.
contract TxOriginNegative {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function adminWithdraw(uint256 amount) external {
        require(msg.sender == owner, "not owner");
        payable(msg.sender).transfer(amount);
    }
}
