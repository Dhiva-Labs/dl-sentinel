// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Fixture contract with no known insecure patterns; a negative control for
// DL Sentinel scanner tests. Never compiled or deployed.
contract Safe {
    mapping(address => uint256) public balances;
    address public immutable owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // Checks-effects-interactions: state is updated before the external call.
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    // msg.sender used for authorization, never tx.origin.
    function adminWithdraw(uint256 amount) external onlyOwner {
        payable(msg.sender).transfer(amount);
    }

    // Minting is restricted to the owner.
    function mint(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
    }
}
