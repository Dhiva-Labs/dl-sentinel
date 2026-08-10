// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Deliberately insecure fixture contract for DL Sentinel scanner tests.
// Never compiled or deployed; a pattern target only.
contract Vulnerable {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // Classic reentrancy: external call before the balance is updated.
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }

    // tx.origin used for authorization instead of msg.sender.
    function adminWithdraw(uint256 amount) external {
        require(tx.origin == owner, "not owner");
        payable(tx.origin).transfer(amount);
    }

    // Unchecked low-level call: the return value is discarded.
    function unsafeCall(address target, bytes calldata data) external {
        target.call(data);
    }

    // Delegatecall to a caller-supplied address.
    function delegateExec(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }

    // Unprotected mint: anyone can create balance out of thin air.
    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }

    // Publicly callable selfdestruct.
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}
