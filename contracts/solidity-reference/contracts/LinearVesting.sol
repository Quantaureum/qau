// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract LinearVesting {
    address public immutable owner;
    uint256 public immutable startTimestamp;
    uint256 public immutable cliffDuration;
    uint256 public immutable vestingDuration;
    uint256 public immutable totalAmount;
    address public immutable beneficiary;
    uint256 public released;

    event Released(uint256 amount);
    event BeneficiaryUpdated(address indexed oldBeneficiary, address indexed newBeneficiary);

    error NotBeneficiary();
    error NoReleasableAmount();
    error CliffNotEnded();
    error ZeroAddress();

    constructor(
        address _beneficiary,
        uint256 _startTimestamp,
        uint256 _cliffDuration,
        uint256 _vestingDuration,
        uint256 _totalAmount
    ) payable {
        if (_beneficiary == address(0)) revert ZeroAddress();
        beneficiary = _beneficiary;
        startTimestamp = _startTimestamp;
        cliffDuration = _cliffDuration;
        vestingDuration = _vestingDuration;
        totalAmount = _totalAmount;
        owner = msg.sender;
    }

    function release() external {
        uint256 releasable = vestedAmount() - released;
        if (releasable == 0) revert NoReleasableAmount();

        released += releasable;
        (bool success, ) = beneficiary.call{value: releasable}("");
        require(success, "Transfer failed");

        emit Released(releasable);
    }

    function vestedAmount() public view returns (uint256) {
        if (block.timestamp < startTimestamp + cliffDuration) {
            return 0;
        }

        if (block.timestamp >= startTimestamp + vestingDuration) {
            return totalAmount;
        }

        uint256 elapsed = block.timestamp - startTimestamp - cliffDuration;
        uint256 vestingPeriod = vestingDuration - cliffDuration;

        return (totalAmount * elapsed) / vestingPeriod;
    }

    function releasableAmount() external view returns (uint256) {
        return vestedAmount() - released;
    }

    receive() external payable {}
}
