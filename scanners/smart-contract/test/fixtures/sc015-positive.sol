// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// Positive fixture for SC015: both bare ERC20 calls discard the bool.
contract UncheckedTransfers {
    IERC20 public token;

    function payout(address to, uint256 amount) external {
        token.transfer(to, amount);
    }

    function pull(address from, uint256 amount) external {
        IERC20(address(token)).transferFrom(from, address(this), amount);
    }
}
