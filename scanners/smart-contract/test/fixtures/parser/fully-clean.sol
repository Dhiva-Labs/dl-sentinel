// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// A contract designed to trigger none of SC001-SC012: exact-pinned recent
// pragma, checks-effects-interactions, msg.sender-based auth, checked calls,
// no delegatecall/selfdestruct, guarded mint/setter with events, no block
// attributes, no deprecated constructs.
contract FullyClean {
    address public owner;
    mapping(address => uint256) public balances;

    event OwnerChanged(address indexed oldOwner, address indexed newOwner);
    event Minted(address indexed to, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function mint(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
        emit Minted(to, amount);
    }

    function setOwner(address newOwner) external onlyOwner {
        address old = owner;
        owner = newOwner;
        emit OwnerChanged(old, newOwner);
    }
}
