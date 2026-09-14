// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

import "./libraries/UQ112x112.sol";
import "./libraries/Math.sol";
import "./interfaces/IERC20Q.sol";
import "./interfaces/IQSwapFactory.sol";
import "./interfaces/IQSwapCallee.sol";

/// @title QSwapPair - AMM Pair for one ERC20/ERC20 pool
/// @dev Simplified Uniswap V2 style constant-product AMM. One pool per token pair.
contract QSwapPair {
    string public constant name = "QSwap LP";
    string public constant symbol = "QSLP";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    address public factory;
    address public authorizedCaller;
    address public token0;
    address public token1;

    uint112 private reserve0;          // uses single storage slot, accessible via getReserves
    uint112 private reserve1;
    uint32  private blockTimestampLast; // used for TWAP oracle

    uint256 public price0CumulativeLast;
    uint256 public price1CumulativeLast;
    uint256 public kLast; // reserve0 * reserve1, as of immediately after the most recent liquidity event

    /// @dev Minimum liquidity locked forever to avoid donation attack on first-LP
    uint256 public constant MINIMUM_LIQUIDITY = 10**3;

    bytes4 private constant SELECTOR = bytes4(keccak256(bytes("transfer(address,uint256)")));

    uint256 private locked = 1;
    modifier lock() {
        require(locked == 1, "QSwap: LOCKED");
        locked = 2;
        _;
        locked = 1;
    }

    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Mint(address indexed sender, uint256 amount0, uint256 amount1);
    event Burn(address indexed sender, uint256 amount0, uint256 amount1, address indexed to);
    event Swap(
        address indexed sender,
        uint256 amount0In,
        uint256 amount1In,
        uint256 amount0Out,
        uint256 amount1Out,
        address indexed to
    );
    event Sync(uint112 reserve0, uint112 reserve1);

    constructor() {
        factory = msg.sender;
    }

    modifier onlyAuthorizedCaller() {
        require(msg.sender == authorizedCaller, "QSwap: FORBIDDEN");
        _;
    }

    // ERC20 basic impl
    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= value, "QSwap: INSUFFICIENT_ALLOWANCE");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - value;
        }
        _transfer(from, to, value);
        return true;
    }

    function _transfer(address from, address to, uint256 value) internal {
        require(balanceOf[from] >= value, "QSwap: INSUFFICIENT_BALANCE");
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }

    // called once by the factory at time of deployment
    function initialize(address _token0, address _token1) external {
        require(msg.sender == factory, "QSwap: FORBIDDEN");
        require(token0 == address(0) && token1 == address(0), "QSwap: INITIALIZED");
        token0 = _token0;
        token1 = _token1;
    }

    function setAuthorizedCaller(address caller) external {
        require(msg.sender == factory, "QSwap: FORBIDDEN");
        require(authorizedCaller == address(0), "QSwap: AUTHORIZED_CALLER_SET");
        require(caller != address(0), "QSwap: ZERO_ADDRESS");
        authorizedCaller = caller;
    }

    function getReserves() public view returns (uint112 _reserve0, uint112 _reserve1, uint32 _blockTimestampLast) {
        _reserve0 = reserve0;
        _reserve1 = reserve1;
        _blockTimestampLast = blockTimestampLast;
    }

    function _safeTransfer(address token, address to, uint256 value) private {
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(SELECTOR, to, value));
        require(success && (data.length == 0 || abi.decode(data, (bool))), "QSwap: TRANSFER_FAILED");
    }

    // update reserves and, on the first call of each block, price accumulators
    function _update(uint256 balance0, uint256 balance1, uint112 _reserve0, uint112 _reserve1) private {
        require(balance0 <= type(uint112).max && balance1 <= type(uint112).max, "QSwap: OVERFLOW");
        uint32 blockTimestamp = uint32(block.timestamp % 2**32);
        uint32 timeElapsed = blockTimestamp - blockTimestampLast;
        if (timeElapsed > 0 && _reserve0 != 0 && _reserve1 != 0) {
            price0CumulativeLast += uint256(UQ112x112.uqdiv(UQ112x112.encode(_reserve1), _reserve0)) * timeElapsed;
            price1CumulativeLast += uint256(UQ112x112.uqdiv(UQ112x112.encode(_reserve0), _reserve1)) * timeElapsed;
        }
        reserve0 = uint112(balance0);
        reserve1 = uint112(balance1);
        blockTimestampLast = blockTimestamp;
        emit Sync(reserve0, reserve1);
    }

    // this low-level function should be called from a contract which performs important safety checks
    function mint(address to) external onlyAuthorizedCaller lock returns (uint256 liquidity) {
        (uint112 _reserve0, uint112 _reserve1,) = getReserves();
        uint256 balance0 = IERC20Q(token0).balanceOf(address(this));
        uint256 balance1 = IERC20Q(token1).balanceOf(address(this));
        uint256 amount0 = balance0 - _reserve0;
        uint256 amount1 = balance1 - _reserve1;

        uint256 _totalSupply = totalSupply;
        if (_totalSupply == 0) {
            liquidity = Math.sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY;
            totalSupply = MINIMUM_LIQUIDITY; // permanently lock the first MINIMUM_LIQUIDITY tokens to dead address
            balanceOf[address(0)] = MINIMUM_LIQUIDITY;
            emit Transfer(address(0), address(0), MINIMUM_LIQUIDITY);
        } else {
            liquidity = Math.min(amount0 * _totalSupply / _reserve0, amount1 * _totalSupply / _reserve1);
        }
        require(liquidity > 0, "QSwap: INSUFFICIENT_LIQUIDITY_MINTED");
        _mint(to, liquidity);

        _update(balance0, balance1, _reserve0, _reserve1);
        kLast = uint256(reserve0) * reserve1;
        emit Mint(msg.sender, amount0, amount1);
    }

    function burn(address to) external onlyAuthorizedCaller lock returns (uint256 amount0, uint256 amount1) {
        (uint112 _reserve0, uint112 _reserve1,) = getReserves();
        address _token0 = token0;
        address _token1 = token1;
        uint256 balance0 = IERC20Q(_token0).balanceOf(address(this));
        uint256 balance1 = IERC20Q(_token1).balanceOf(address(this));
        uint256 liquidity = balanceOf[address(this)];

        uint256 _totalSupply = totalSupply;
        amount0 = liquidity * balance0 / _totalSupply; // using balances ensures pro-rata distribution
        amount1 = liquidity * balance1 / _totalSupply;
        require(amount0 > 0 && amount1 > 0, "QSwap: INSUFFICIENT_LIQUIDITY_BURNED");
        _burn(address(this), liquidity);
        _safeTransfer(_token0, to, amount0);
        _safeTransfer(_token1, to, amount1);
        balance0 = IERC20Q(_token0).balanceOf(address(this));
        balance1 = IERC20Q(_token1).balanceOf(address(this));

        _update(balance0, balance1, _reserve0, _reserve1);
        kLast = uint256(reserve0) * reserve1;
        emit Burn(msg.sender, amount0, amount1, to);
    }

    // this low-level function should be called from a contract which performs important safety checks
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external onlyAuthorizedCaller lock {
        require(amount0Out > 0 || amount1Out > 0, "QSwap: INSUFFICIENT_OUTPUT_AMOUNT");
        (uint112 _reserve0, uint112 _reserve1,) = getReserves();
        require(amount0Out < _reserve0 && amount1Out < _reserve1, "QSwap: INSUFFICIENT_LIQUIDITY");

        uint256 balance0;
        uint256 balance1;
        {
            address _token0 = token0;
            address _token1 = token1;
            require(to != _token0 && to != _token1, "QSwap: INVALID_TO");
            if (amount0Out > 0) _safeTransfer(_token0, to, amount0Out); // optimistically transfer tokens
            if (amount1Out > 0) _safeTransfer(_token1, to, amount1Out);
            if (data.length > 0) IQSwapCallee(to).qswapCall(msg.sender, amount0Out, amount1Out, data);
            balance0 = IERC20Q(_token0).balanceOf(address(this));
            balance1 = IERC20Q(_token1).balanceOf(address(this));
        }
        uint256 amount0In = balance0 > _reserve0 - amount0Out ? balance0 - (_reserve0 - amount0Out) : 0;
        uint256 amount1In = balance1 > _reserve1 - amount1Out ? balance1 - (_reserve1 - amount1Out) : 0;
        require(amount0In > 0 || amount1In > 0, "QSwap: INSUFFICIENT_INPUT_AMOUNT");
        {
            // scope for reserve{0,1}Adjusted, avoids stack too deep errors
            uint256 balance0Adjusted = balance0 * 1000 - (amount0In * 3); // 0.3% fee
            uint256 balance1Adjusted = balance1 * 1000 - (amount1In * 3);
            require(balance0Adjusted * balance1Adjusted >= uint256(_reserve0) * _reserve1 * (1000**2), "QSwap: K");
        }

        _update(balance0, balance1, _reserve0, _reserve1);
        emit Swap(msg.sender, amount0In, amount1In, amount0Out, amount1Out, to);
    }

    // force balances to match reserves
    function skim(address to) external lock {
        address _token0 = token0;
        address _token1 = token1;
        _safeTransfer(_token0, to, IERC20Q(_token0).balanceOf(address(this)) - reserve0);
        _safeTransfer(_token1, to, IERC20Q(_token1).balanceOf(address(this)) - reserve1);
    }

    // force reserves to match balances
    function sync() external lock {
        _update(IERC20Q(token0).balanceOf(address(this)), IERC20Q(token1).balanceOf(address(this)), reserve0, reserve1);
    }

    function _mint(address to, uint256 value) internal {
        totalSupply += value;
        balanceOf[to] += value;
        emit Transfer(address(0), to, value);
    }

    function _burn(address from, uint256 value) internal {
        balanceOf[from] -= value;
        totalSupply -= value;
        emit Transfer(from, address(0), value);
    }
}
