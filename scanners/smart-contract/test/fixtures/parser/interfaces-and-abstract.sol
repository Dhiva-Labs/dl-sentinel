// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// Interface: every function is a body-less stub.
interface IToken {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// Abstract contract: a mix of an unimplemented virtual stub and an
// implemented function. Only the implemented one should be treated as
// having a body.
abstract contract BaseToken {
    uint256 public totalSupply;

    function balanceOf(address account) public view virtual returns (uint256);

    function mint(address to, uint256 amount) public virtual {
        totalSupply += amount;
    }
}
