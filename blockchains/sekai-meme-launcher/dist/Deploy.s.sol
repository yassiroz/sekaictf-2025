// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-ctf/CTFDeployer.sol";
import "forge-ctf/CTFChallenge.sol";

import "src/MemeManager.sol";

contract Deploy is CTFDeployer {
    function deploy(address system, address player) internal override returns (CTFChallenge[] memory challenges) {
        vm.startBroadcast(system);

        // player
        address factory = 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f;
        address router = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
        address weth = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
        MemeManager memeManager = new MemeManager{value: 100 ether}(system, factory, router, weth, player);

        challenges = new CTFChallenge[](1);
        challenges[0] = CTFChallenge("MemeManager", address(memeManager));

        vm.stopBroadcast();
    }
}
