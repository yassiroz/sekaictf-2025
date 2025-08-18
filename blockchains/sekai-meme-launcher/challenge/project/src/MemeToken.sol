// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {ERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

contract MemeToken is ERC20 {
    address public immutable MANAGER;

    error NotManager();

    constructor(string memory name_, string memory symbol_, address MANAGER_) ERC20(name_, symbol_) {
        require(MANAGER_ != address(0), "MemeToken: manager is zero");
        MANAGER = MANAGER_;
    }

    function mint(address to, uint256 amount) external {
        if (msg.sender != MANAGER) revert NotManager();
        _mint(to, amount);
    }
}