// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Positive fixture for SC016: privileged addresses assigned straight from a
// parameter with nothing rejecting address(0).
contract ZeroAddressUnchecked {
    address public owner;
    address public treasury;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event TreasuryUpdated(address indexed newTreasury);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function setTreasury(address newTreasury) external onlyOwner {
        treasury = newTreasury;
        emit TreasuryUpdated(newTreasury);
    }
}
