// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { LinearVesting } from "./LinearVesting.sol";

contract VestingFactory {
    address public immutable governance;

    struct VestingSchedule {
        address contractAddress;
        address beneficiary;
        uint256 totalAmount;
        uint256 startTimestamp;
        uint256 cliffDuration;
        uint256 vestingDuration;
        string category;
    }

    VestingSchedule[] public schedules;

    event VestingCreated(
        address indexed contractAddress,
        address indexed beneficiary,
        uint256 totalAmount,
        uint256 cliffDuration,
        uint256 vestingDuration,
        string category
    );

    modifier onlyGovernance() {
        require(msg.sender == governance, "Only governance");
        _;
    }

    constructor() {
        governance = msg.sender;
    }

    function createVesting(
        address beneficiary,
        uint256 startTimestamp,
        uint256 cliffDuration,
        uint256 vestingDuration,
        string calldata category
    ) external payable onlyGovernance returns (address) {
        require(beneficiary != address(0), "Zero address");
        require(msg.value > 0, "Zero amount");
        require(vestingDuration > cliffDuration, "Invalid durations");

        LinearVesting vesting = (new LinearVesting){value: msg.value}(
            beneficiary,
            startTimestamp,
            cliffDuration,
            vestingDuration,
            msg.value
        );

        schedules.push(VestingSchedule({
            contractAddress: address(vesting),
            beneficiary: beneficiary,
            totalAmount: msg.value,
            startTimestamp: startTimestamp,
            cliffDuration: cliffDuration,
            vestingDuration: vestingDuration,
            category: category
        }));

        emit VestingCreated(
            address(vesting),
            beneficiary,
            msg.value,
            cliffDuration,
            vestingDuration,
            category
        );

        return address(vesting);
    }

    function getScheduleCount() external view returns (uint256) {
        return schedules.length;
    }

    function getSchedule(uint256 index) external view returns (VestingSchedule memory) {
        require(index < schedules.length, "Index out of bounds");
        return schedules[index];
    }

    function getAllSchedules() external view returns (VestingSchedule[] memory) {
        return schedules;
    }
}
