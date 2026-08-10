// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

// Pre-0.5 Solidity: omitted function visibility defaults to `public`.
contract LegacyVisibility {
    uint256 public value;

    function setValue(uint256 v) {
        value = v;
    }

    function explicitInternal(uint256 v) internal {
        value = v;
    }
}
