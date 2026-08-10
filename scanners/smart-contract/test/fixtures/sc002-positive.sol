// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Positive fixture for SC002: tx.origin used for authorization.
contract TxOriginPositive {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function adminWithdraw(uint256 amount) external {
        require(tx.origin == owner, "not owner");
        payable(tx.origin).transfer(amount);
    }
}
