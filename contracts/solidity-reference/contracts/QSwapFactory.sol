// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

import "./QSwapPair.sol";

/// @title QSwapFactory - Deploys and indexes QSwap pairs
/// @dev Deterministic pair addresses via CREATE2, so callers can derive the token pair without RPC lookup.
contract QSwapFactory {
    address public feeTo;
    address public feeToSetter;
    address public pairCaller;

    mapping(address => mapping(address => address)) public getPair;
    address[] public allPairs;

    event PairCreated(address indexed token0, address indexed token1, address pair, uint256);

    constructor(address _feeToSetter) {
        feeToSetter = _feeToSetter;
    }

    function setPairCaller(address _pairCaller) external {
        require(msg.sender == feeToSetter, "QSwap: FORBIDDEN");
        require(pairCaller == address(0), "QSwap: PAIR_CALLER_SET");
        require(_pairCaller != address(0), "QSwap: ZERO_ADDRESS");
        pairCaller = _pairCaller;
    }

    function allPairsLength() external view returns (uint256) {
        return allPairs.length;
    }

    function createPair(address tokenA, address tokenB) external returns (address pair) {
        require(tokenA != tokenB, "QSwap: IDENTICAL_ADDRESSES");
        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        require(token0 != address(0), "QSwap: ZERO_ADDRESS");
        require(getPair[token0][token1] == address(0), "QSwap: PAIR_EXISTS");

        bytes memory bytecode = type(QSwapPair).creationCode;
        bytes32 salt = keccak256(abi.encodePacked(token0, token1));
        assembly {
            pair := create2(0, add(bytecode, 32), mload(bytecode), salt)
        }
        require(pairCaller != address(0), "QSwap: PAIR_CALLER_NOT_SET");
        QSwapPair(pair).initialize(token0, token1);
        QSwapPair(pair).setAuthorizedCaller(pairCaller);

        getPair[token0][token1] = pair;
        getPair[token1][token0] = pair; // populate mapping in the reverse direction
        allPairs.push(pair);
        emit PairCreated(token0, token1, pair, allPairs.length);
    }

    function setFeeTo(address _feeTo) external {
        require(msg.sender == feeToSetter, "QSwap: FORBIDDEN");
        feeTo = _feeTo;
    }

    function setFeeToSetter(address _feeToSetter) external {
        require(msg.sender == feeToSetter, "QSwap: FORBIDDEN");
        feeToSetter = _feeToSetter;
    }
}
