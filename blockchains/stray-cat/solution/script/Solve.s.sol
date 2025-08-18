// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {Solve} from "../src/Solve.sol";

contract CounterScript is Script {
    Solve public solve;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        solve = new Solve();

        vm.stopBroadcast();
    }
}
