// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

library SafeERC20 {
    function safeTransfer(IERC20 t, address to, uint256 amount) internal {
        require(t.transfer(to, amount), "transfer failed");
    }
}

// Negative fixture for SC015: every near-miss the rule must stay quiet on.
contract CheckedTransfers {
    using SafeERC20 for IERC20;

    IERC20 public token;

    // Wrapped in require: checked.
    function requiredTransfer(address to, uint256 amount) external {
        require(token.transfer(to, amount), "transfer failed");
    }

    // Captured into a bool: checked.
    function capturedTransfer(address to, uint256 amount) external returns (bool) {
        bool ok = token.transfer(to, amount);
        return ok;
    }

    // The SafeERC20 idiom: a different method name entirely.
    function safeTransferOut(address to, uint256 amount) external {
        token.safeTransfer(to, amount);
    }

    // An ETH transfer, not an ERC20 one: one argument, and the receiver is not
    // a token handle. Must never be confused for the ERC20 shape.
    function sendEther(address payable to, uint256 amount) external {
        to.transfer(amount);
    }
}
