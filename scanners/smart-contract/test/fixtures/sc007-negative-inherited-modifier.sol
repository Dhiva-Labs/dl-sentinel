// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Negative fixture for SC007: the guard is declared two contracts up the
// inheritance chain, so only same-file inheritance resolution can see it.
contract Owned {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }
}

abstract contract TokenBase is Owned {
    mapping(address => uint256) public balances;
}

contract InheritedGuardToken is TokenBase {
    function mint(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
    }
}
