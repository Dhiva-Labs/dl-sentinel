// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Positive fixture for SC013, direction B: withdraw() writes state itself, but
// the external call that must come after it is buried in _payout(). SC001
// cannot see this — withdraw() contains no external call of its own.
contract CrossFunctionCallViaHop {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        _payout(msg.sender, amount);
        balances[msg.sender] -= amount;
    }

    function _payout(address to, uint256 amount) internal {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
