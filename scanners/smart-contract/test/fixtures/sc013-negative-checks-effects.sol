// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Negative fixture for SC013: checks-effects-interactions held ACROSS the hop.
// The effects happen inside _settle(), which runs before the external call, so
// there is nothing for a re-entrant caller to observe stale.
contract CrossFunctionChecksEffects {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        _settle(msg.sender, amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function _settle(address account, uint256 amount) internal {
        balances[account] -= amount;
    }
}
