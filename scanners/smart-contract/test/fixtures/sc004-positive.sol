// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Positive fixture for SC004: delegatecall target comes from a parameter.
contract DelegatecallPositive {
    function execute(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}
