// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Negative fixture for SC005: selfdestruct is guarded by an onlyOwner modifier.
contract SelfdestructNegative {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function destroy() external onlyOwner {
        selfdestruct(payable(owner));
    }
}
