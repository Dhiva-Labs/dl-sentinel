// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Negative fixture for SC011: modern equivalents of each deprecated
// construct in sc011-positive.sol.
contract DeprecatedNegative {
    function modernHash(bytes memory data) public pure returns (bytes32) {
        return keccak256(data);
    }

    function modernVar() public pure returns (uint256) {
        uint256 x = 1;
        return x;
    }

    function modernRevert(uint256 value) public pure {
        require(value != 0, "value is zero");
    }

    function modernDestroy() public {
        selfdestruct(payable(msg.sender));
    }

    function modernDelegate(address target, bytes memory data) public {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}
