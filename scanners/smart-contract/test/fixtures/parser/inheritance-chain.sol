// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Model fixture: a three-level inheritance chain in one file, plus an
// unresolvable (imported) base, plus a call graph deep enough to exercise the
// traversal bound. Rules are not the subject here — resolve.ts is.

// Stands in for an import the scanner cannot see.
interface IExternalBase {
    function ping() external view returns (bool);
}

contract Ownership {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function transferOwnershipInternal(address newOwner) internal {
        owner = newOwner;
    }
}

abstract contract Pausable is Ownership {
    bool public paused;

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    function pause() external onlyOwner {
        paused = true;
    }
}

// `Vault is Pausable, Imported` — Pausable resolves in-file (and drags
// Ownership in behind it); Imported does not exist here at all.
contract Vault is Pausable, Imported {
    mapping(address => uint256) public balances;

    // Guarded only by a modifier declared two contracts up the chain.
    function drain(address to) external onlyOwner {
        balances[to] = 0;
    }

    function levelOne() internal {
        levelTwo();
    }

    function levelTwo() internal {
        levelThree();
    }

    function levelThree() internal {
        levelFour();
    }

    function levelFour() internal {
        paused = false;
    }

    function entry() external {
        levelOne();
    }
}
