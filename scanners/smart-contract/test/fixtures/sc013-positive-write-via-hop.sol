// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Positive fixture for SC013, direction A: the external call is a statement of
// withdraw() itself, but the balance update it should have done first happens
// one call hop away, inside _settle(). SC001 cannot see this — withdraw()
// contains no state write of its own.
contract CrossFunctionWriteViaHop {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        _settle(msg.sender, amount);
    }

    function _settle(address account, uint256 amount) internal {
        balances[account] -= amount;
    }
}
