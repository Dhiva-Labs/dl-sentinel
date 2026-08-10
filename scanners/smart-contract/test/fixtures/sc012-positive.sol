// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Positive fixture for SC012: owner setter with no event emission.
contract SetterNoEventPositive {
    address public owner;

    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}
