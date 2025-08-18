// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "lib/openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {VC} from "./vc.sol";
import {MemeToken} from "./MemeToken.sol";
import {IUniswapV2Factory} from "./interfaces/IUniswapV2Factory.sol";
import {IUniswapV2Router02} from "./interfaces/IUniswapV2Router02.sol";
import {IUniswapV2Pair} from "./interfaces/IUniswapV2Pair.sol";
import {IWETH} from "./interfaces/IWETH.sol";

contract MemeManager is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    struct MemeInfo {
        address token;
        address pair;
        address creator;
        uint256 initialPriceWeiPerToken;
        bool initialLiquidityProvided;
    }

    uint256 public constant MEME_AMOUNT = 100_000 * 1e18;

    address public FACTORY;
    address public ROUTER;
    address public WETH;
    address public operator;
    address public player;
    VC public vc;

    mapping(address => MemeInfo) public tokenInfo;
    address[] public allTokens;

    event OperatorUpdated(address indexed oldOperator, address indexed newOperator);
    event MemeCreated(address indexed creator, address indexed token, address pair, string name, string symbol);
    event MemeCreatedWithInitialLiquidity(
        address indexed operator,
        address indexed token,
        address pair,
        uint256 priceWeiPerToken,
        uint256 amountETH,
        uint256 amountToken,
        uint256 liquidity
    );
    event LiquidityProvided(address indexed token, uint256 amountToken, uint256 amountETH, uint256 liquidity);

    function isSolved() public view returns (bool) {
        if(player.balance >= 50 * 1e18) return true;
        return false;
    }
    modifier onlyOperator() {
        require(msg.sender == operator, "MemeManager: not operator");
        _;
    }

    constructor(address initialOwner, address FACTORY_, address ROUTER_, address WETH_, address player_)
        Ownable(initialOwner) payable
    {
        require(FACTORY_ != address(0) && ROUTER_ != address(0) && WETH_ != address(0), "MemeManager: zero");
        FACTORY = FACTORY_;
        ROUTER = ROUTER_;
        WETH = WETH_;
        player = player_;
        vc = new VC{value: 100 * 1e18}(address(this));
    }

    receive() external payable {}

    function setOperator(address newOperator) external onlyOwner {
        emit OperatorUpdated(operator, newOperator);
        operator = newOperator;
        vc.setOperator(newOperator);
    }

    function getAllTokens() external view returns (address[] memory) {
        return allTokens;
    }

    function _createMeme(address creator, string calldata name, string calldata symbol, uint256 initialPrice)
        internal
        returns (address token, address pair)
    {
        MemeToken t = new MemeToken(name, symbol, address(this));
        token = address(t);

        pair = IUniswapV2Factory(FACTORY).getPair(token, WETH);
        if (pair == address(0)) {
            pair = IUniswapV2Factory(FACTORY).createPair(token, WETH);
        }

        tokenInfo[token] = MemeInfo({
            token: token,
            pair: pair,
            creator: creator,
            initialPriceWeiPerToken: initialPrice,
            initialLiquidityProvided: false
        });
        allTokens.push(token);

        emit MemeCreated(creator, token, pair, name, symbol);
    }

    function createMeme(string calldata name, string calldata symbol, uint256 initialPrice) external returns (address token, address pair) {
        return _createMeme(msg.sender, name, symbol, initialPrice);
    }

    function createMemeAndProvideInitialLiquidity(
        string calldata name,
        string calldata symbol,
        uint256 priceWeiPerToken,
        uint256 deadline
    ) external nonReentrant returns (address token, address pair, uint256 amountToken, uint256 amountETHUsed, uint256 liquidity) {
        require(priceWeiPerToken > 0, "MemeManager: price=0");
        require(priceWeiPerToken <= 0.0001 * 1e18, "MemeManager: price too big");

        (token, pair) = _createMeme(msg.sender, name, symbol, priceWeiPerToken);

        amountToken = MEME_AMOUNT;
        require(amountToken > 0, "MemeManager: token=0");
        uint256 requiredETH = (amountToken * priceWeiPerToken) / 1e18;

        MemeInfo storage info = tokenInfo[token];
        info.initialPriceWeiPerToken = priceWeiPerToken;
        require(!info.initialLiquidityProvided, "MemeManager: already init");
        info.initialLiquidityProvided = true;

        MemeToken(token).mint(address(this), amountToken);

        vc.giveMeETH(payable(address(this)), requiredETH);

        IERC20(token).safeIncreaseAllowance(ROUTER, amountToken);

        (amountToken, amountETHUsed, liquidity) = IUniswapV2Router02(ROUTER).addLiquidityETH{value: requiredETH}(
            token,
            amountToken,
            amountToken, 
            requiredETH, 
            address(vc),
            deadline
        );

        emit MemeCreatedWithInitialLiquidity(msg.sender, token, pair, priceWeiPerToken, amountETHUsed, amountToken, liquidity);
    }

    function ProvideLiquidity(
        address token,
        uint256 deadline
    ) external nonReentrant returns (uint256 amountToken, uint256 amountETHUsed, uint256 liquidity) {
        MemeInfo storage info = tokenInfo[token];
        require(info.token != address(0), "MemeManager: unknown token");

        uint256 priceWeiPerToken = info.initialPriceWeiPerToken;
        require(priceWeiPerToken > 0, "MemeManager: price=0");
        require(priceWeiPerToken <= 0.0001 * 1e18, "MemeManager: price too big");

        uint256 amountTokenDesired = MEME_AMOUNT;
        require(amountTokenDesired > 0, "MemeManager: token=0");

        uint256 requiredETH = (amountTokenDesired * priceWeiPerToken) / 1e18;

        require(!info.initialLiquidityProvided, "MemeManager: already init");
        info.initialLiquidityProvided = true;
        info.initialPriceWeiPerToken = priceWeiPerToken;

        MemeToken(token).mint(address(this), amountTokenDesired);

        vc.giveMeETH(payable(address(this)), requiredETH);
        IERC20(token).safeIncreaseAllowance(ROUTER, amountTokenDesired);
        (amountToken, amountETHUsed, liquidity) = IUniswapV2Router02(ROUTER).addLiquidityETH{value: requiredETH}(
            token,
            amountTokenDesired,
            amountTokenDesired, 
            requiredETH,       
            address(vc),
            deadline
        );

        emit LiquidityProvided(token, amountToken, amountETHUsed, liquidity);
    }

    function preSale(address token, uint256 amount) external payable {
        MemeInfo memory info = tokenInfo[token];
        require(info.token != address(0), "MemeManager: unknown token");
        require(!info.initialLiquidityProvided, "MemeManager: preSale ended");
        require(msg.value >= 0.5 * 1e18, "MemeManager: too little");
        require(msg.value * 1e18 == amount * info.initialPriceWeiPerToken, "MemeManager: wrong amount");

        MemeToken(token).mint(msg.sender, amount);
    }

    function swap() external payable returns (bytes memory error){
        assembly {
            let valueLeft := callvalue()
            let n:= shr(248, calldataload(4))
            let cur
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {

                cur := add(5, mul(0x14, i))
                let token := shr(96, calldataload(cur))

                cur := add(cur, mul(n, 0x14))
                let amount:= calldataload(cur)

                cur := add(cur, mul(n, 0x20))
                let dir:= shr(248, calldataload(cur))

                let ptr := mload(0x40)

                switch dir
                case 1 {
                    mstore(ptr, 0x7ff36ab500000000000000000000000000000000000000000000000000000000)
                    mstore(add(ptr, 0x04), 0)
                    mstore(add(ptr, 0x24), 0x80)
                    mstore(add(ptr, 0x44), caller())
                    mstore(add(ptr, 0x64), timestamp())
                    let tail := add(ptr, 0x84)
                    mstore(tail, 2)
                    mstore(add(tail, 0x20), sload(WETH.slot))
                    mstore(add(tail, 0x40), token)
                    let ok := call(gas(), sload(ROUTER.slot), amount, ptr, add(0x84, 0x60), 0, 0)
                    let rd := returndatasize()
                    if iszero(ok) { returndatacopy(0, 0, rd) revert(0, rd) }
                    valueLeft := sub(valueLeft, amount)
                }
                default {
                    mstore(ptr, 0x23b872dd00000000000000000000000000000000000000000000000000000000)
                    mstore(add(ptr, 0x04), caller())
                    mstore(add(ptr, 0x24), address())
                    mstore(add(ptr, 0x44), amount)
                    let ok := call(gas(), token, 0, ptr, 0x64, 0, 0)
                    let rd := returndatasize()
                    if iszero(ok) { returndatacopy(0, 0, rd) revert(0, rd) }

                    mstore(ptr, 0x095ea7b300000000000000000000000000000000000000000000000000000000)
                    mstore(add(ptr, 0x04), sload(ROUTER.slot))
                    mstore(add(ptr, 0x24), amount)
                    ok := call(gas(), token, 0, ptr, 0x44, 0, 0)
                    rd := returndatasize()
                    if iszero(ok) { returndatacopy(0, 0, rd) revert(0, rd) }

                    mstore(ptr, 0x18cbafe500000000000000000000000000000000000000000000000000000000)
                    mstore(add(ptr, 0x04), amount)
                    mstore(add(ptr, 0x24), 0)
                    mstore(add(ptr, 0x44), 0xa0)
                    mstore(add(ptr, 0x64), caller())
                    mstore(add(ptr, 0x84), timestamp())
                    let tail2 := add(ptr, 0xa4)
                    mstore(tail2, 2)
                    mstore(add(tail2, 0x20), token)
                    mstore(add(tail2, 0x40), sload(WETH.slot))
                    ok := call(gas(), sload(ROUTER.slot), 0, ptr, add(0xa4, 0x60), 0, 0)
                    rd := returndatasize()
                    if iszero(ok) { returndatacopy(0, 0, rd) revert(0, rd) }
                }
            }
        }
    }
}


