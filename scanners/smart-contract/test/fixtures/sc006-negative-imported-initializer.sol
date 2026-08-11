// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Negative fixture for SC006: the OpenZeppelin upgradeable pattern. The
// `initializer` modifier comes from a base this file does not contain, so its
// body is unreadable and it is assumed protective — the documented "assumed"
// verdict, and the gap the old name-only heuristic could not close.
contract UpgradeableToken is Initializable {
    address public owner;
    string public name;

    function initialize(address newOwner, string memory tokenName) external initializer {
        owner = newOwner;
        name = tokenName;
    }
}
