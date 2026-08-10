// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Three sequential (sibling) top-level declarations in one file: an
// interface, a library, and a contract that "inherits" it. Solidity does
// not nest contract declarations, so this exercises the parser's ability to
// reset correctly between top-level blocks and keep each one's state
// variables/functions from leaking into the others.
interface IGreeter {
    function greet() external view returns (string memory);
}

library Math {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
}

contract Greeter is IGreeter {
    string public message;
    uint256 public counter;

    constructor(string memory initialMessage) {
        message = initialMessage;
    }

    function greet() external view override returns (string memory) {
        return message;
    }

    function bump() external {
        counter = Math.add(counter, 1);
    }
}

contract SecondContract {
    uint256 public value;

    function setValue(uint256 v) external {
        value = v;
    }
}
