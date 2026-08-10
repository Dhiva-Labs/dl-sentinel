// SPDX-License-Identifier: MIT
pragma solidity 0.7.6;

// Positive fixture for SC009: exact-pinned but outdated — its upper reach
// (0.7.6) never gets to Solidity 0.8.
contract OutdatedPragmaPositive {
    uint256 public value;
}
