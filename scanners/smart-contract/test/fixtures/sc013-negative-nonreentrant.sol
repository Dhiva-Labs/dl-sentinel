// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Negative fixture for SC013: the vulnerable cross-function shape, but the
// ENTRY function carries a reentrancy guard, which suppresses the rule.
contract CrossFunctionGuarded {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "insufficient balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        _settle(msg.sender, amount);
    }

    function _settle(address account, uint256 amount) internal {
        balances[account] -= amount;
    }
}
