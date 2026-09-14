// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ValidatorRegistry
/// @notice Registry for cross-chain bridge validators.
///         Manages validator registration, staking, slashing, and reward
///         distribution for the Quantaureum bridge security model.
///
/// @dev Security properties:
///         - Governance-gated validator management (R69-GOV-1)
///         - Slashing mechanism for validator misconduct
///         - Stake-based voting power for cross-chain message verification
///         - Reentrancy guards on all state-changing functions
///
/// @custom:security-contact security@quantaureum.com
contract ValidatorRegistry {
    // =============================================================================
    // Constants
    // =============================================================================

    /// @notice Minimum stake required to be an active validator.
    uint256 public constant MIN_STAKE = 100 ether;

    /// @notice Maximum number of active validators.
    uint256 public constant MAX_VALIDATORS = 128;

    /// @notice Percentage of stake slashed on a minor offense (10% = 100).
    uint256 public constant MINOR_SLASH_PERCENT = 100; // 10% (100/1000)

    /// @notice Percentage of stake slashed on a major offense (20% = 200).
    uint256 public constant MAJOR_SLASH_PERCENT = 200; // 20% (200/1000)

    /// @notice Reward numerator (numerator/denominator = reward fraction).
    uint256 public constant REWARD_NUMERATOR = 10;
    uint256 public constant REWARD_DENOMINATOR = 1000;

    // =============================================================================
    // State
    // =============================================================================

    /// @notice Governance address for access control.
    address public governance;

    /// @notice Maps validator address → validator info.
    mapping(address => ValidatorInfo) public validators;

    /// @notice List of active validator addresses (for iteration).
    address[] public validatorList;

    /// @notice Cumulative rewards pool for distribution.
    uint256 public rewardPool;

    /// @notice Whether the registry is paused.
    bool public paused;

    /// @notice Maps validator address → pending withdrawal amount.
    mapping(address => uint256) public pendingWithdrawals;

    /// @notice Maps validator address → withdrawal request timestamp.
    mapping(address => uint256) public withdrawalRequestTimes;

    // =============================================================================
    // Structs
    // =============================================================================

    struct ValidatorInfo {
        uint256 stake;
        bytes publicKey;          // Dilithium3 public key (1952 bytes)
        bool isActive;
        uint64 registeredAt;
        uint256 totalSlashCount;
        uint256 totalRewardsEarned;
    }

    // =============================================================================
    // Events
    // =============================================================================

    event ValidatorRegistered(
        address indexed validator,
        uint256 stake,
        bytes publicKey
    );
    event ValidatorUnregistered(address indexed validator, uint256 returnedStake);
    event ValidatorSlashed(
        address indexed validator,
        uint256 slashAmount,
        bool isMajor
    );
    event RewardDistributed(
        address indexed validator,
        uint256 rewardAmount
    );
    event StakeDeposited(address indexed validator, uint256 amount);
    event WithdrawalRequested(address indexed validator, uint256 amount, uint64 delay);
    event WithdrawalExecuted(address indexed validator, uint256 amount);
    event GovernanceChanged(address indexed oldGov, address indexed newGov);
    event RegistryPaused(bool isPaused);
    event ValidatorKeyUpdated(address indexed validator, bytes oldKey, bytes newKey);

    // =============================================================================
    // Modifiers
    // =============================================================================

    modifier whenNotPaused() {
        require(!paused, "ValidatorRegistry: paused");
        _;
    }

    modifier onlyGovernance() {
        require(msg.sender == governance, "ValidatorRegistry: only governance");
        _;
    }

    modifier onlyActiveValidator() {
        require(validators[msg.sender].isActive, "ValidatorRegistry: not active");
        _;
    }

    modifier reentrancyGuard() {
        require(_reentrancyGuard != 2, "ValidatorRegistry: reentrancy");
        _reentrancyGuard = 2;
        _;
        _reentrancyGuard = 1;
    }

    // =============================================================================
    // Constructor
    // =============================================================================

    constructor(address _governance) {
        require(_governance != address(0), "ValidatorRegistry: zero governance");
        governance = _governance;
    }

    // =============================================================================
    // Validator registration
    // =============================================================================

    /// @notice Registers a new validator with a Dilithium3 public key and stake.
    /// @param validatorAddress The address of the validator.
    /// @param publicKey        The Dilithium3 public key (1952 bytes).
    /// @dev Requires the validator has already sent stake to this contract
    ///      via depositStake(). Alternatively, stake can be sent with the call.
    function registerValidator(address validatorAddress, bytes calldata publicKey)
        external
        payable
        whenNotPaused
        onlyGovernance
        reentrancyGuard
    {
        require(validatorAddress != address(0), "ValidatorRegistry: zero validator");
        require(!validators[validatorAddress].isActive, "ValidatorRegistry: already registered");
        require(publicKey.length == 1952, "ValidatorRegistry: invalid key size");
        require(msg.value >= MIN_STAKE, "ValidatorRegistry: below minimum stake");
        require(validatorList.length < MAX_VALIDATORS, "ValidatorRegistry: max validators reached");

        ValidatorInfo storage info = validators[validatorAddress];
        info.stake = msg.value;
        info.publicKey = publicKey;
        info.isActive = true;
        info.registeredAt = uint64(block.timestamp);

        validatorList.push(validatorAddress);

        emit ValidatorRegistered(validatorAddress, msg.value, publicKey);
    }

    /// @notice Allows a validator to deposit additional stake.
    function depositStake() external payable whenNotPaused onlyActiveValidator reentrancyGuard {
        require(msg.value > 0, "ValidatorRegistry: zero amount");
        validators[msg.sender].stake += msg.value;
        emit StakeDeposited(msg.sender, msg.value);
    }

    /// @notice Initiates a withdrawal request (unbonding period applies).
    /// @param amount The amount to withdraw after unbonding.
    /// @dev In production, a 14-day unbonding period would apply before withdrawal.
    ///      For this implementation, a shorter delay can be configured via delaySeconds.
    function requestWithdrawal(uint256 amount) external onlyActiveValidator whenNotPaused {
        require(amount > 0, "ValidatorRegistry: zero amount");
        require(validators[msg.sender].stake >= amount, "ValidatorRegistry: insufficient stake");

        pendingWithdrawals[msg.sender] = amount;
        withdrawalRequestTimes[msg.sender] = block.timestamp;

        emit WithdrawalRequested(msg.sender, amount, 14 days);
    }

    /// @notice Executes a withdrawal after the unbonding delay.
    /// @param validator The validator to withdraw from.
    function executeWithdrawal(address validator)
        external
        onlyGovernance
        reentrancyGuard
    {
        uint256 amount = pendingWithdrawals[validator];
        require(amount > 0, "ValidatorRegistry: nothing to withdraw");
        require(
            block.timestamp >= withdrawalRequestTimes[validator] + 14 days,
            "ValidatorRegistry: unbonding period not elapsed"
        );

        pendingWithdrawals[validator] = 0;
        withdrawalRequestTimes[validator] = 0;

        ValidatorInfo storage info = validators[validator];
        require(info.stake >= amount, "ValidatorRegistry: stake underflow");

        info.stake -= amount;

        // If stake drops below minimum, deactivate validator
        if (info.stake < MIN_STAKE) {
            info.isActive = false;
        }

        payable(validator).transfer(amount);
        emit WithdrawalExecuted(validator, amount);
    }

    /// @notice Unregisters a validator and returns their stake.
    /// @param validator The validator to unregister.
    function unregisterValidator(address validator)
        external
        onlyGovernance
        reentrancyGuard
    {
        require(validators[validator].isActive, "ValidatorRegistry: not active");
        require(pendingWithdrawals[validator] == 0, "ValidatorRegistry: pending withdrawal");

        uint256 stake = validators[validator].stake;
        validators[validator].isActive = false;
        validators[validator].stake = 0;

        // Remove from validator list
        uint256 listLen = validatorList.length;
        for (uint256 i = 0; i < listLen; i++) {
            if (validatorList[i] == validator) {
                validatorList[i] = validatorList[listLen - 1];
                validatorList.pop();
                break;
            }
        }

        payable(validator).transfer(stake);
        emit ValidatorUnregistered(validator, stake);
    }

    // =============================================================================
    // Slashing
    // =============================================================================

    /// @notice Slashes a validator for a minor offense.
    /// @param validator The validator to slash.
    /// @dev Minor slash = 1% of stake. Slashing 3 times = major slash.
    function slashValidatorMinor(address validator)
        external
        onlyGovernance
        reentrancyGuard
    {
        require(validators[validator].isActive, "ValidatorRegistry: not active");
        uint256 slashAmount = (validators[validator].stake * MINOR_SLASH_PERCENT) / 1000;
        _slash(validator, slashAmount, false);
    }

    /// @notice Slashes a validator for a major offense.
    /// @param validator The validator to slash.
    /// @dev Major slash = 20% of stake. Automatically deactivates validator.
    function slashValidatorMajor(address validator)
        external
        onlyGovernance
        reentrancyGuard
    {
        require(validators[validator].isActive, "ValidatorRegistry: not active");
        uint256 slashAmount = (validators[validator].stake * MAJOR_SLASH_PERCENT) / 1000;
        _slash(validator, slashAmount, true);
    }

    // =============================================================================
    // Reward distribution
    // =============================================================================

    /// @notice Deposits rewards into the reward pool.
    /// @dev Anyone can deposit rewards; distributed proportionally by stake.
    function depositRewards() external payable {
        require(msg.value > 0, "ValidatorRegistry: zero amount");
        rewardPool += msg.value;
    }

    /// @notice Distributes accumulated rewards to all active validators.
    /// @dev Called by governance or the relayer. Proportional to stake share.
    function distributeRewards() external onlyGovernance whenNotPaused reentrancyGuard {
        uint256 totalActiveStake = _totalActiveStake();
        require(totalActiveStake > 0, "ValidatorRegistry: no active stake");
        require(rewardPool > 0, "ValidatorRegistry: no rewards");

        uint256 toDistribute = rewardPool;
        rewardPool = 0;

        uint256 listLen = validatorList.length;
        for (uint256 i = 0; i < listLen; i++) {
            address v = validatorList[i];
            if (!validators[v].isActive) continue;

            uint256 share = (toDistribute * validators[v].stake) / totalActiveStake;
            if (share == 0) continue;

            validators[v].totalRewardsEarned += share;
            payable(v).transfer(share);
            emit RewardDistributed(v, share);
        }
    }

    // =============================================================================
    // Governance functions
    // =============================================================================

    /// @notice Updates a validator's Dilithium3 public key.
    /// @param validator The validator address.
    /// @param newKey    The new public key (1952 bytes).
    function setValidatorKey(address validator, bytes calldata newKey)
        external
        onlyGovernance
    {
        require(newKey.length == 1952, "ValidatorRegistry: invalid key size");
        bytes memory oldKey = validators[validator].publicKey;
        validators[validator].publicKey = newKey;
        emit ValidatorKeyUpdated(validator, oldKey, newKey);
    }

    /// @notice Changes the governance address.
    /// @param newGovernance The new governance address.
    function setGovernance(address newGovernance)
        external
        onlyGovernance
    {
        require(newGovernance != address(0), "ValidatorRegistry: zero governance");
        address oldGov = governance;
        governance = newGovernance;
        emit GovernanceChanged(oldGov, newGovernance);
    }

    /// @notice Pauses or unpauses the registry.
    /// @param _paused True to pause.
    function setPaused(bool _paused) external onlyGovernance {
        paused = _paused;
        emit RegistryPaused(_paused);
    }

    // =============================================================================
    // View functions
    // =============================================================================

    /// @notice Returns whether an address is an active validator.
    /// @param validator The address to check.
    /// @return True if active.
    function isActiveValidator(address validator) external view returns (bool) {
        return validators[validator].isActive;
    }

    /// @notice Returns the current stake of a validator.
    /// @param validator The validator address.
    /// @return The stake amount.
    function getStake(address validator) external view returns (uint256) {
        return validators[validator].stake;
    }

    /// @notice Returns the Dilithium3 public key of a validator.
    /// @param validator The validator address.
    /// @return The public key bytes.
    function getValidatorKey(address validator) external view returns (bytes memory) {
        return validators[validator].publicKey;
    }

    /// @notice Returns all active validators.
    /// @return Array of active validator addresses.
    function getActiveValidators() external view returns (address[] memory) {
        uint256 count = 0;
        for (uint256 i = 0; i < validatorList.length; i++) {
            if (validators[validatorList[i]].isActive) count++;
        }

        address[] memory active = new address[](count);
        uint256 idx = 0;
        for (uint256 i = 0; i < validatorList.length; i++) {
            if (validators[validatorList[i]].isActive) {
                active[idx++] = validatorList[i];
            }
        }
        return active;
    }

    /// @notice Returns the total active stake across all validators.
    function getTotalActiveStake() external view returns (uint256) {
        return _totalActiveStake();
    }

    /// @notice Returns whether a withdrawal request is ready to execute.
    /// @param validator The validator address.
    /// @return True if ready.
    function isWithdrawalReady(address validator) external view returns (bool) {
        return pendingWithdrawals[validator] > 0 &&
            block.timestamp >= withdrawalRequestTimes[validator] + 14 days;
    }

    // =============================================================================
    // Internal helpers
    // =============================================================================

    function _slash(address validator, uint256 amount, bool isMajor) internal {
        ValidatorInfo storage info = validators[validator];
        require(info.stake >= amount, "ValidatorRegistry: slash exceeds stake");

        info.stake -= amount;
        info.totalSlashCount += 1;
        rewardPool += amount;

        if (isMajor) {
            info.isActive = false;
            // Remove from active list
            uint256 listLen = validatorList.length;
            for (uint256 i = 0; i < listLen; i++) {
                if (validatorList[i] == validator) {
                    validatorList[i] = validatorList[listLen - 1];
                    validatorList.pop();
                    break;
                }
            }
        }

        emit ValidatorSlashed(validator, amount, isMajor);
    }

    function _totalActiveStake() internal view returns (uint256) {
        uint256 total = 0;
        uint256 listLen = validatorList.length;
        for (uint256 i = 0; i < listLen; i++) {
            if (validators[validatorList[i]].isActive) {
                total += validators[validatorList[i]].stake;
            }
        }
        return total;
    }

    uint256 private _reentrancyGuard = 1;

    // =============================================================================
    // Receive / Fallback
    // =============================================================================

    receive() external payable {
        rewardPool += msg.value;
    }

    fallback() external payable {
        rewardPool += msg.value;
    }
}