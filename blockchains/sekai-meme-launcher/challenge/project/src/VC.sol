// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {IUniswapV2Router02} from "./interfaces/IUniswapV2Router02.sol";
import {IUniswapV2Factory} from "./interfaces/IUniswapV2Factory.sol";
import {IUniswapV2Pair} from "./interfaces/IUniswapV2Pair.sol";
import {IWETH} from "./interfaces/IWETH.sol";

contract VC is Ownable {
    using SafeERC20 for IERC20;

    address public operator;

    event OperatorUpdated(address indexed oldOperator, address indexed newOperator);
    event LiquidityAdded(address indexed token, uint256 amountToken, uint256 amountETH, uint256 liquidity);
    event ETHDeposited(address indexed from, uint256 amount);
    event ETHWithdrawn(address indexed to, uint256 amount);
    event TokenWithdrawn(address indexed token, address indexed to, uint256 amount);

    modifier onlyOperator() {
        require(msg.sender == operator, "VC: not operator");
        _;
    }

    constructor(address initialOwner) Ownable(initialOwner) payable {
        operator = initialOwner;
    }

    receive() external payable {
        emit ETHDeposited(msg.sender, msg.value);
    }

    function setOperator(address newOperator) external onlyOwner {
        emit OperatorUpdated(operator, newOperator);
        operator = newOperator;
    }

    function ethBalance() external view returns (uint256) {
        return address(this).balance;
    }

    function tokenBalance(address token) external view returns (uint256) {
        return IERC20(token).balanceOf(address(this));
    }

    function giveMeETH(address payable to, uint256 amount) external onlyOperator {
        require(address(this).balance >= amount, "VC: insufficient ETH");
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "VC: ETH transfer failed");
        emit ETHWithdrawn(to, amount);
    }
}


