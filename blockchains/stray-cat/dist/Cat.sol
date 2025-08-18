// SPDX-License-Identifier: MIT
// Fixed version to avoid foundry/4668
pragma solidity 0.8.27;

contract Cat {
    event Purr();
    function gibheadpats() public {
        revert("*sniff sniff HISS HISS* hooman detected....");
        emit Purr();
    }
}
