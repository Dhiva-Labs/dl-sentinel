// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Traversal-bound fixture for SC013. Both contracts have the identical shape;
// only the distance from the entry point to the state write differs.

// The write sits three hops out (entry -> _hopOne -> _hopTwo -> _hopThree),
// exactly at the bound, so it is still reachable and the rule fires.
contract DepthWithinBound {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        _hopOne(msg.sender, amount);
    }

    function _hopOne(address account, uint256 amount) internal {
        _hopTwo(account, amount);
    }

    function _hopTwo(address account, uint256 amount) internal {
        _hopThree(account, amount);
    }

    function _hopThree(address account, uint256 amount) internal {
        balances[account] -= amount;
    }
}

// The same chain with one more link: the write is four hops out, past the
// bound, so nothing is reported. This is under-reporting by design.
contract DepthBeyondBound {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        _hopOne(msg.sender, amount);
    }

    function _hopOne(address account, uint256 amount) internal {
        _hopTwo(account, amount);
    }

    function _hopTwo(address account, uint256 amount) internal {
        _hopThree(account, amount);
    }

    function _hopThree(address account, uint256 amount) internal {
        _hopFour(account, amount);
    }

    function _hopFour(address account, uint256 amount) internal {
        balances[account] -= amount;
    }
}
