// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

/// @title WQAU - Wrapped Quantaureum Native Token
/// @notice Wraps native QAU into an ERC-20 token. 1 QAU deposited = 1 WQAU minted.
///         Anyone holding WQAU can withdraw the underlying QAU 1:1 at any time.
contract WQAU {
    string public constant name = "Wrapped QAU";
    string public constant symbol = "WQAU";
    uint8 public constant decimals = 18;

    event Approval(address indexed src, address indexed guy, uint256 wad);
    event Transfer(address indexed src, address indexed dst, uint256 wad);
    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    receive() external payable {
        deposit();
    }

    fallback() external payable {
        deposit();
    }

    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 wad) public {
        require(balanceOf[msg.sender] >= wad, "WQAU: insufficient balance");
        balanceOf[msg.sender] -= wad;
        (bool success, ) = msg.sender.call{value: wad}("");
        require(success, "WQAU: ETH transfer failed");
        emit Withdrawal(msg.sender, wad);
    }

    function totalSupply() public view returns (uint256) {
        return address(this).balance;
    }

    function approve(address guy, uint256 wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
        return true;
    }

    function transfer(address dst, uint256 wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(
        address src,
        address dst,
        uint256 wad
    ) public returns (bool) {
        require(balanceOf[src] >= wad, "WQAU: insufficient balance");

        if (src != msg.sender) {
            uint256 allowed = allowance[src][msg.sender];
            require(allowed >= wad, "WQAU: insufficient allowance");
            if (allowed != type(uint256).max) {
                allowance[src][msg.sender] = allowed - wad;
            }
        }

        balanceOf[src] -= wad;
        balanceOf[dst] += wad;

        emit Transfer(src, dst, wad);
        return true;
    }
}
