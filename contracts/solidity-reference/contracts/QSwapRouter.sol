// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

import "./interfaces/IERC20Q.sol";
import "./interfaces/IQSwapFactory.sol";
import "./QSwapPair.sol";
import "./interfaces/IWQAU.sol";
import "./libraries/Math.sol";
import "./libraries/QSwapLibrary.sol";
import "./libraries/TransferHelper.sol";

/// @title QSwapRouter - user-facing routing layer for QSwap
/// @notice Users interact with this contract, never with pairs directly.
/// @dev Routes swaps through the optimal pair path. Supports any ERC-20, plus native QAU via WQAU.
contract QSwapRouter {
    address public immutable factory;
    address public immutable WQAU_ADDRESS;

    modifier ensure(uint256 deadline) {
        require(deadline >= block.timestamp, "QSwapRouter: EXPIRED");
        _;
    }

    constructor(address _factory, address _wQau) {
        factory = _factory;
        WQAU_ADDRESS = _wQau;
    }

    receive() external payable {
        // Only accept QAU via fallback from the WQAU contract
        assert(msg.sender == WQAU_ADDRESS);
    }

    // **** ADD LIQUIDITY ****
    function _addLiquidity(
        address tokenA,
        address tokenB,
        uint256 amountADesired,
        uint256 amountBDesired,
        uint256 amountAMin,
        uint256 amountBMin
    ) internal view returns (uint256 amountA, uint256 amountB) {
        // create the pair if it doesn't exist yet
        if (IQSwapFactory(factory).getPair(tokenA, tokenB) == address(0)) {
            revert("QSwapRouter: PAIR_DOES_NOT_EXIST");
        }
        (uint256 reserveA, uint256 reserveB) = QSwapLibrary.getReserves(factory, tokenA, tokenB);
        if (reserveA == 0 && reserveB == 0) {
            (amountA, amountB) = (amountADesired, amountBDesired);
        } else {
            uint256 amountBOptimal = QSwapLibrary.quote(amountADesired, reserveA, reserveB);
            if (amountBOptimal <= amountBDesired) {
                require(amountBOptimal >= amountBMin, "QSwapRouter: INSUFFICIENT_B_AMOUNT");
                (amountA, amountB) = (amountADesired, amountBOptimal);
            } else {
                uint256 amountAOptimal = QSwapLibrary.quote(amountBDesired, reserveB, reserveA);
                assert(amountAOptimal <= amountADesired);
                require(amountAOptimal >= amountAMin, "QSwapRouter: INSUFFICIENT_A_AMOUNT");
                (amountA, amountB) = (amountAOptimal, amountBDesired);
            }
        }
    }

    function addLiquidity(
        address tokenA,
        address tokenB,
        uint256 amountADesired,
        uint256 amountBDesired,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline
    ) external ensure(deadline) returns (uint256 amountA, uint256 amountB, uint256 liquidity) {
        (amountA, amountB) = _addLiquidity(tokenA, tokenB, amountADesired, amountBDesired, amountAMin, amountBMin);
        address pair = QSwapLibrary.pairFor(factory, tokenA, tokenB);
        TransferHelper.safeTransferFrom(tokenA, msg.sender, pair, amountA);
        TransferHelper.safeTransferFrom(tokenB, msg.sender, pair, amountB);
        liquidity = QSwapPair(pair).mint(to);
    }

    function addLiquidityQau(
        address token,
        uint256 amountTokenDesired,
        uint256 amountTokenMin,
        uint256 amountQauMin,
        address to,
        uint256 deadline
    ) external payable ensure(deadline) returns (uint256 amountToken, uint256 amountQau, uint256 liquidity) {
        (amountToken, amountQau) = _addLiquidity(
            token,
            WQAU_ADDRESS,
            amountTokenDesired,
            msg.value,
            amountTokenMin,
            amountQauMin
        );
        address pair = QSwapLibrary.pairFor(factory, token, WQAU_ADDRESS);
        TransferHelper.safeTransferFrom(token, msg.sender, pair, amountToken);
        IWQAU(WQAU_ADDRESS).deposit{value: amountQau}();
        assert(IWQAU(WQAU_ADDRESS).transfer(pair, amountQau));
        liquidity = QSwapPair(pair).mint(to);
        // refund dust QAU, if any
        if (msg.value > amountQau) TransferHelper.safeTransferQau(msg.sender, msg.value - amountQau);
    }

    // **** REMOVE LIQUIDITY ****
    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint256 liquidity,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline
    ) public ensure(deadline) returns (uint256 amountA, uint256 amountB) {
        address pair = QSwapLibrary.pairFor(factory, tokenA, tokenB);
        QSwapPair(pair).transferFrom(msg.sender, pair, liquidity); // send liquidity to pair
        (uint256 amount0, uint256 amount1) = QSwapPair(pair).burn(to);
        (address token0,) = QSwapLibrary.sortTokens(tokenA, tokenB);
        (amountA, amountB) = tokenA == token0 ? (amount0, amount1) : (amount1, amount0);
        require(amountA >= amountAMin, "QSwapRouter: INSUFFICIENT_A_AMOUNT");
        require(amountB >= amountBMin, "QSwapRouter: INSUFFICIENT_B_AMOUNT");
    }

    function removeLiquidityQau(
        address token,
        uint256 liquidity,
        uint256 amountTokenMin,
        uint256 amountQauMin,
        address to,
        uint256 deadline
    ) public ensure(deadline) returns (uint256 amountToken, uint256 amountQau) {
        (amountToken, amountQau) = removeLiquidity(
            token,
            WQAU_ADDRESS,
            liquidity,
            amountTokenMin,
            amountQauMin,
            address(this),
            deadline
        );
        TransferHelper.safeTransfer(token, to, amountToken);
        IWQAU(WQAU_ADDRESS).withdraw(amountQau);
        TransferHelper.safeTransferQau(to, amountQau);
    }

    // **** SWAP ****
    // requires the initial amount to have already been sent to the first pair
    function _swap(uint256[] memory amounts, address[] memory path, address _to) internal {
        for (uint256 i; i < path.length - 1; i++) {
            (address input, address output) = (path[i], path[i + 1]);
            (address token0,) = QSwapLibrary.sortTokens(input, output);
            uint256 amountOut = amounts[i + 1];
            (uint256 amount0Out, uint256 amount1Out) = input == token0
                ? (uint256(0), amountOut)
                : (amountOut, uint256(0));
            address to = i < path.length - 2
                ? QSwapLibrary.pairFor(factory, output, path[i + 2])
                : _to;
            QSwapPair(QSwapLibrary.pairFor(factory, input, output)).swap(amount0Out, amount1Out, to, new bytes(0));
        }
    }

    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external ensure(deadline) returns (uint256[] memory amounts) {
        amounts = QSwapLibrary.getAmountsOut(factory, amountIn, path);
        require(amounts[amounts.length - 1] >= amountOutMin, "QSwapRouter: INSUFFICIENT_OUTPUT_AMOUNT");
        TransferHelper.safeTransferFrom(path[0], msg.sender, QSwapLibrary.pairFor(factory, path[0], path[1]), amounts[0]);
        _swap(amounts, path, to);
    }

    function swapTokensForExactTokens(
        uint256 amountOut,
        uint256 amountInMax,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external ensure(deadline) returns (uint256[] memory amounts) {
        amounts = QSwapLibrary.getAmountsIn(factory, amountOut, path);
        require(amounts[0] <= amountInMax, "QSwapRouter: EXCESSIVE_INPUT_AMOUNT");
        TransferHelper.safeTransferFrom(path[0], msg.sender, QSwapLibrary.pairFor(factory, path[0], path[1]), amounts[0]);
        _swap(amounts, path, to);
    }

    function swapExactQauForTokens(
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable ensure(deadline) returns (uint256[] memory amounts) {
        require(path[0] == WQAU_ADDRESS, "QSwapRouter: INVALID_PATH");
        amounts = QSwapLibrary.getAmountsOut(factory, msg.value, path);
        require(amounts[amounts.length - 1] >= amountOutMin, "QSwapRouter: INSUFFICIENT_OUTPUT_AMOUNT");
        IWQAU(WQAU_ADDRESS).deposit{value: amounts[0]}();
        assert(IWQAU(WQAU_ADDRESS).transfer(QSwapLibrary.pairFor(factory, path[0], path[1]), amounts[0]));
        _swap(amounts, path, to);
    }

    function swapTokensForExactQau(
        uint256 amountOut,
        uint256 amountInMax,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external ensure(deadline) returns (uint256[] memory amounts) {
        require(path[path.length - 1] == WQAU_ADDRESS, "QSwapRouter: INVALID_PATH");
        amounts = QSwapLibrary.getAmountsIn(factory, amountOut, path);
        require(amounts[0] <= amountInMax, "QSwapRouter: EXCESSIVE_INPUT_AMOUNT");
        TransferHelper.safeTransferFrom(path[0], msg.sender, QSwapLibrary.pairFor(factory, path[0], path[1]), amounts[0]);
        _swap(amounts, path, address(this));
        IWQAU(WQAU_ADDRESS).withdraw(amounts[amounts.length - 1]);
        TransferHelper.safeTransferQau(to, amounts[amounts.length - 1]);
    }

    function swapExactTokensForQau(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external ensure(deadline) returns (uint256[] memory amounts) {
        require(path[path.length - 1] == WQAU_ADDRESS, "QSwapRouter: INVALID_PATH");
        amounts = QSwapLibrary.getAmountsOut(factory, amountIn, path);
        require(amounts[amounts.length - 1] >= amountOutMin, "QSwapRouter: INSUFFICIENT_OUTPUT_AMOUNT");
        TransferHelper.safeTransferFrom(path[0], msg.sender, QSwapLibrary.pairFor(factory, path[0], path[1]), amounts[0]);
        _swap(amounts, path, address(this));
        IWQAU(WQAU_ADDRESS).withdraw(amounts[amounts.length - 1]);
        TransferHelper.safeTransferQau(to, amounts[amounts.length - 1]);
    }

    function swapQauForExactTokens(
        uint256 amountOut,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable ensure(deadline) returns (uint256[] memory amounts) {
        require(path[0] == WQAU_ADDRESS, "QSwapRouter: INVALID_PATH");
        amounts = QSwapLibrary.getAmountsIn(factory, amountOut, path);
        require(amounts[0] <= msg.value, "QSwapRouter: EXCESSIVE_INPUT_AMOUNT");
        IWQAU(WQAU_ADDRESS).deposit{value: amounts[0]}();
        assert(IWQAU(WQAU_ADDRESS).transfer(QSwapLibrary.pairFor(factory, path[0], path[1]), amounts[0]));
        _swap(amounts, path, to);
        // refund dust QAU, if any
        if (msg.value > amounts[0]) TransferHelper.safeTransferQau(msg.sender, msg.value - amounts[0]);
    }

    // **** LIBRARY FUNCTIONS ****
    function quote(uint256 amountA, uint256 reserveA, uint256 reserveB) external pure returns (uint256) {
        return QSwapLibrary.quote(amountA, reserveA, reserveB);
    }

    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) external pure returns (uint256) {
        return QSwapLibrary.getAmountOut(amountIn, reserveIn, reserveOut);
    }

    function getAmountIn(uint256 amountOut, uint256 reserveIn, uint256 reserveOut) external pure returns (uint256) {
        return QSwapLibrary.getAmountIn(amountOut, reserveIn, reserveOut);
    }

    function getAmountsOut(uint256 amountIn, address[] memory path) external view returns (uint256[] memory) {
        return QSwapLibrary.getAmountsOut(factory, amountIn, path);
    }

    function getAmountsIn(uint256 amountOut, address[] memory path) external view returns (uint256[] memory) {
        return QSwapLibrary.getAmountsIn(factory, amountOut, path);
    }
}
