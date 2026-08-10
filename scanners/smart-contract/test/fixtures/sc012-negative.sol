// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Negative fixture for SC012: owner setter emits an event.
contract SetterWithEventNegative {
    address public owner;

    event OwnerChanged(address indexed oldOwner, address indexed newOwner);

    function setOwner(address newOwner) external {
        address old = owner;
        owner = newOwner;
        emit OwnerChanged(old, newOwner);
    }
}
