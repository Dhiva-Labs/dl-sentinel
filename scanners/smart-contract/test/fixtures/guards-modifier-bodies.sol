// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Fixture for guards.ts: the shapes a modifier's BODY can take, and what each
// one must resolve to. Rule behavior is asserted elsewhere; this file exists to
// pin the three-way proven/assumed/none verdict.
contract ModifierBodies {
    address public owner;
    mapping(address => uint256) public wards;

    // proven: a direct equality against the caller.
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // proven: the caller appears in the condition, just not as its own operand.
    modifier auth() {
        require(wards[msg.sender] == 1, "not authorized");
        _;
    }

    // proven: a recognized authorization helper the file does not declare.
    modifier onlyRole(bytes32 role) {
        _checkRole(role);
        _;
    }

    // proven, one hop out: the check lives in an in-file helper.
    modifier onlyOwnerIndirect() {
        require(isOwner(), "not owner");
        _;
    }

    // none: protective-sounding name, body that guards nothing at all.
    modifier onlyOwnerButEmpty() {
        _;
    }

    // none: a real modifier, but not an access-control one.
    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    bool public paused;

    function isOwner() internal view returns (bool) {
        return msg.sender == owner;
    }
}

// A base whose modifier is declared but left for a child to implement: its
// body cannot be read, so it resolves to "assumed".
abstract contract AbstractGuard {
    modifier onlyGovernor() virtual;
}
