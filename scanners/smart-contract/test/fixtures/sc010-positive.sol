// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Positive fixture for SC010: block.timestamp modulo feeds a winner pick.
contract RandomnessPositive {
    address[] public players;

    function pickWinner() external view returns (address) {
        uint256 index = block.timestamp % players.length;
        return players[index];
    }
}
