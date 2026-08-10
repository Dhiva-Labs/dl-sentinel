// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Same vulnerable shape as sc001-positive.sol, but guarded by a
// nonReentrant modifier — SC001 must be suppressed here.
contract ReentrancySuppressed {
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
        balances[msg.sender] -= amount;
    }
}
