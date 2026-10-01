import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

describe("ValidatorRegistry", function () {
  let registry: any;
  let governance: string;
  let validator1: string;
  let validator2: string;
  const MIN_STAKE = 100n; // 100 ether in test (scaled down from 100 ether for faster tests)

  beforeEach(async function () {
    const [signer1, signer2, signer3] = await ethers.getSigners();
    governance = await signer1.getAddress();
    validator1 = await signer2.getAddress();
    validator2 = await signer3.getAddress();

    const RegistryFactory = await ethers.getContractFactory("ValidatorRegistry");
    registry = await RegistryFactory.deploy(governance);
    await registry.waitForDeployment();
  });

  // ---------------------------------------------------------------------------
  // Constructor
  // ---------------------------------------------------------------------------

  describe("Constructor", function () {
    it("should deploy with governance set", async function () {
      expect(await registry.governance()).to.equal(governance);
    });

    it("should revert when governance is zero address", async function () {
      const RegistryFactory = await ethers.getContractFactory("ValidatorRegistry");
      await expect(
        RegistryFactory.deploy(ethers.ZeroAddress)
      ).to.be.revertedWith("ValidatorRegistry: zero governance");
    });
  });

  // ---------------------------------------------------------------------------
  // Validator registration
  // ---------------------------------------------------------------------------

  describe("registerValidator", function () {
    function dummyKey(): `0x${string}` {
      return ("0x" + "44".repeat(1952)) as `0x${string}`;
    }

    it("should let governance register a validator with sufficient stake", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];

      const registryAsGov = registry.connect(govSigner as any);

      // Fund the registry with ETH for the stake
      await signers[0].sendTransaction({
        to: registry.target,
        value: ethers.parseEther("150"),
      });

      await registryAsGov.registerValidator(validator1, dummyKey(), {
        value: ethers.parseEther("150"),
      });

      expect(await registry.isActiveValidator(validator1)).to.equal(true);
      expect(await registry.getStake(validator1)).to.equal(ethers.parseEther("150"));
    });

    it("should emit ValidatorRegistered event", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];

      const registryAsGov = registry.connect(govSigner as any);
      await signers[0].sendTransaction({
        to: registry.target,
        value: ethers.parseEther("200"),
      });

      await expect(
        registryAsGov.registerValidator(validator1, dummyKey(), {
          value: ethers.parseEther("200"),
        })
      )
        .to.emit(registry, "ValidatorRegistered")
        .withArgs(validator1, ethers.parseEther("200"), dummyKey());
    });

    it("should revert when non-governance calls registerValidator", async function () {
      const signers = await ethers.getSigners();
      const nonGov = signers[2];

      const registryAsNonGov = registry.connect(nonGov as any);
      await expect(
        registryAsNonGov.registerValidator(validator1, dummyKey(), {
          value: ethers.parseEther("200"),
        })
      ).to.be.revertedWith("ValidatorRegistry: only governance");
    });

    it("should revert when validator address is zero", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];

      const registryAsGov = registry.connect(govSigner as any);
      await signers[0].sendTransaction({
        to: registry.target,
        value: ethers.parseEther("200"),
      });

      await expect(
        registryAsGov.registerValidator(ethers.ZeroAddress, dummyKey(), {
          value: ethers.parseEther("200"),
        })
      ).to.be.revertedWith("ValidatorRegistry: zero validator");
    });

    it("should revert when validator already registered", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];

      const registryAsGov = registry.connect(govSigner as any);
      await signers[0].sendTransaction({
        to: registry.target,
        value: ethers.parseEther("300"),
      });

      await registryAsGov.registerValidator(validator1, dummyKey(), {
        value: ethers.parseEther("200"),
      });

      // Try to register again
      await expect(
        registryAsGov.registerValidator(validator1, dummyKey(), {
          value: ethers.parseEther("200"),
        })
      ).to.be.revertedWith("ValidatorRegistry: already registered");
    });

    it("should revert when stake is below minimum", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];

      const registryAsGov = registry.connect(govSigner as any);
      await signers[0].sendTransaction({
        to: registry.target,
        value: ethers.parseEther("50"),
      });

      await expect(
        registryAsGov.registerValidator(validator1, dummyKey(), {
          value: ethers.parseEther("50"),
        })
      ).to.be.revertedWith("ValidatorRegistry: below minimum stake");
    });

    it("should revert when key size is invalid", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];

      const registryAsGov = registry.connect(govSigner as any);
      await signers[0].sendTransaction({
        to: registry.target,
        value: ethers.parseEther("200"),
      });

      const badKey = ("0x" + "44".repeat(100)) as `0x${string}`;
      await expect(
        registryAsGov.registerValidator(validator1, badKey, {
          value: ethers.parseEther("200"),
        })
      ).to.be.revertedWith("ValidatorRegistry: invalid key size");
    });
  });

  // ---------------------------------------------------------------------------
  // Deposit additional stake
  // ---------------------------------------------------------------------------

  describe("depositStake", function () {
    async function registerValidator(valAddress: string) {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const registryAsGov = registry.connect(govSigner as any);
      await signers[0].sendTransaction({
        to: registry.target,
        value: ethers.parseEther("200"),
      });
      const dummyKey = ("0x" + "55".repeat(1952)) as `0x${string}`;
      await registryAsGov.registerValidator(valAddress, dummyKey, {
        value: ethers.parseEther("200"),
      });
    }

    it("should let active validator deposit additional stake", async function () {
      await registerValidator(validator1);
      const signers = await ethers.getSigners();
      const validatorSigner = signers[1];
      const valAsSigner = registry.connect(validatorSigner as any);

      const initialStake = await registry.getStake(validator1);
      await valAsSigner.depositStake({ value: ethers.parseEther("50") });

      expect(await registry.getStake(validator1)).to.equal(initialStake + ethers.parseEther("50"));
    });

    it("should emit StakeDeposited event", async function () {
      await registerValidator(validator1);
      const signers = await ethers.getSigners();
      const validatorSigner = signers[1];
      const valAsSigner = registry.connect(validatorSigner as any);

      await expect(valAsSigner.depositStake({ value: ethers.parseEther("50") }))
        .to.emit(registry, "StakeDeposited")
        .withArgs(validator1, ethers.parseEther("50"));
    });

    it("should revert when non-active validator deposits", async function () {
      const signers = await ethers.getSigners();
      const validatorSigner = signers[1];
      const valAsSigner = registry.connect(validatorSigner as any);

      await expect(
        valAsSigner.depositStake({ value: ethers.parseEther("50") })
      ).to.be.revertedWith("ValidatorRegistry: not active");
    });

    it("should revert when deposit amount is zero", async function () {
      await registerValidator(validator1);
      const signers = await ethers.getSigners();
      const validatorSigner = signers[1];
      const valAsSigner = registry.connect(validatorSigner as any);

      await expect(valAsSigner.depositStake({ value: 0n })).to.be.revertedWith(
        "ValidatorRegistry: zero amount"
      );
    });
  });

  // ---------------------------------------------------------------------------
  // Withdrawal
  // ---------------------------------------------------------------------------

  describe("requestWithdrawal", function () {
    async function registerValidator(valAddress: string) {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const registryAsGov = registry.connect(govSigner as any);
      await signers[0].sendTransaction({
        to: registry.target,
        value: ethers.parseEther("200"),
      });
      const dummyKey = ("0x" + "66".repeat(1952)) as `0x${string}`;
      await registryAsGov.registerValidator(valAddress, dummyKey, {
        value: ethers.parseEther("200"),
      });
    }

    it("should let active validator request withdrawal", async function () {
      await registerValidator(validator1);
      const signers = await ethers.getSigners();
      const validatorSigner = signers[1];
      const valAsSigner = registry.connect(validatorSigner as any);

      await valAsSigner.requestWithdrawal(ethers.parseEther("50"));

      const isReady = await registry.isWithdrawalReady(validator1);
      expect(isReady).to.equal(false); // Not ready yet (unbonding period not elapsed)
    });

    it("should revert when non-active validator requests withdrawal", async function () {
      const signers = await ethers.getSigners();
      const nonValidator = signers[3];
      const nonValAsSigner = registry.connect(nonValidator as any);

      await expect(
        nonValAsSigner.requestWithdrawal(ethers.parseEther("50"))
      ).to.be.revertedWith("ValidatorRegistry: not active");
    });

    it("should revert when withdrawal amount exceeds stake", async function () {
      await registerValidator(validator1);
      const signers = await ethers.getSigners();
      const validatorSigner = signers[1];
      const valAsSigner = registry.connect(validatorSigner as any);

      await expect(
        valAsSigner.requestWithdrawal(ethers.parseEther("500"))
      ).to.be.revertedWith("ValidatorRegistry: insufficient stake");
    });
  });

  describe("executeWithdrawal", function () {
    async function registerAndRequestWithdrawal(valAddress: string) {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const registryAsGov = registry.connect(govSigner as any);
      await signers[0].sendTransaction({
        to: registry.target,
        value: ethers.parseEther("200"),
      });
      const dummyKey = ("0x" + "77".repeat(1952)) as `0x${string}`;
      await registryAsGov.registerValidator(valAddress, dummyKey, {
        value: ethers.parseEther("200"),
      });

      const validatorSigner = signers[1];
      const valAsSigner = registry.connect(validatorSigner as any);
      await valAsSigner.requestWithdrawal(ethers.parseEther("50"));
    }

    it("should revert when unbonding period not elapsed", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const validatorSigner = signers[1];

      const registryAsGov = registry.connect(govSigner as any);
      await signers[0].sendTransaction({
        to: registry.target,
        value: ethers.parseEther("250"),
      });
      const dummyKey = ("0x" + "77".repeat(1952)) as `0x${string}`;
      // validator1 = signers[1].address
      await registryAsGov.registerValidator(validator1, dummyKey, {
        value: ethers.parseEther("200"),
      });

      // validator1 requests withdrawal
      const valAsSigner = registry.connect(validatorSigner as any);
      await valAsSigner.requestWithdrawal(ethers.parseEther("50"));

      // Try to execute immediately (should fail due to unbonding period)
      await expect(
        registryAsGov.executeWithdrawal(validator1)
      ).to.be.revertedWith("ValidatorRegistry: unbonding period not elapsed");
    });

    it("should succeed after unbonding period", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const validatorSigner = signers[1];

      const registryAsGov = registry.connect(govSigner as any);
      await signers[0].sendTransaction({
        to: registry.target,
        value: ethers.parseEther("250"),
      });
      const dummyKey = ("0x" + "77".repeat(1952)) as `0x${string}`;
      await registryAsGov.registerValidator(validator1, dummyKey, {
        value: ethers.parseEther("200"),
      });

      // validator1 requests withdrawal
      const valAsSigner = registry.connect(validatorSigner as any);
      await valAsSigner.requestWithdrawal(ethers.parseEther("50"));

      // Advance time past the 14-day unbonding period
      await time.increase(14 * 24 * 60 * 60 + 1);

      const validatorBalanceBefore = await ethers.provider.getBalance(validator1);
      await registryAsGov.executeWithdrawal(validator1);
      const validatorBalanceAfter = await ethers.provider.getBalance(validator1);

      expect(validatorBalanceAfter - validatorBalanceBefore).to.equal(ethers.parseEther("50"));
    });
  });

  // ---------------------------------------------------------------------------
  // Slashing
  // ---------------------------------------------------------------------------

  describe("slashValidatorMinor", function () {
    async function registerValidator(valAddress: string, stake: bigint) {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const registryAsGov = registry.connect(govSigner as any);
      await signers[0].sendTransaction({
        to: registry.target,
        value: stake + ethers.parseEther("1"),
      });
      const dummyKey = ("0x" + "88".repeat(1952)) as `0x${string}`;
      await registryAsGov.registerValidator(valAddress, dummyKey, {
        value: stake,
      });
    }

    it("should slash a validator minor and add to reward pool", async function () {
      const stake = ethers.parseEther("200");
      await registerValidator(validator1, stake);

      const govSigner = (await ethers.getSigners())[0];
      const registryAsGov = registry.connect(govSigner as any);

      const rewardPoolBefore = await registry.rewardPool();
      await registryAsGov.slashValidatorMinor(validator1);
      const rewardPoolAfter = await registry.rewardPool();

      // 10% of 200 ETH = 20 ETH
      expect(rewardPoolAfter - rewardPoolBefore).to.equal(ethers.parseEther("20"));
      expect(await registry.getStake(validator1)).to.equal(ethers.parseEther("180"));
    });

    it("should emit ValidatorSlashed event", async function () {
      const stake = ethers.parseEther("200");
      await registerValidator(validator1, stake);

      const govSigner = (await ethers.getSigners())[0];
      const registryAsGov = registry.connect(govSigner as any);

      await expect(registryAsGov.slashValidatorMinor(validator1))
        .to.emit(registry, "ValidatorSlashed")
        .withArgs(validator1, ethers.parseEther("20"), false);
    });

    it("should revert when non-governance slashes", async function () {
      const stake = ethers.parseEther("200");
      await registerValidator(validator1, stake);

      const nonGov = (await ethers.getSigners())[2];
      const registryAsNonGov = registry.connect(nonGov as any);

      await expect(
        registryAsNonGov.slashValidatorMinor(validator1)
      ).to.be.revertedWith("ValidatorRegistry: only governance");
    });

    it("should revert when slashing inactive validator", async function () {
      const govSigner = (await ethers.getSigners())[0];
      const registryAsGov = registry.connect(govSigner as any);

      await expect(
        registryAsGov.slashValidatorMinor(validator1)
      ).to.be.revertedWith("ValidatorRegistry: not active");
    });
  });

  describe("slashValidatorMajor", function () {
    async function registerValidator(valAddress: string, stake: bigint) {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const registryAsGov = registry.connect(govSigner as any);
      // Fund the validator's address so they have gas for the registration tx
      await govSigner.sendTransaction({
        to: valAddress,
        value: ethers.parseEther("1"),
      });
      const dummyKey = ("0x" + "99".repeat(1952)) as `0x${string}`;
      await registryAsGov.registerValidator(valAddress, dummyKey, {
        value: stake,
      });
    }

    it("should slash major and deactivate validator", async function () {
      const stake = ethers.parseEther("100");
      await registerValidator(validator1, stake);

      const govSigner = (await ethers.getSigners())[0];
      const registryAsGov = registry.connect(govSigner as any);

      await registryAsGov.slashValidatorMajor(validator1);

      expect(await registry.isActiveValidator(validator1)).to.equal(false);
      // 20% of 100 ETH = 20 ETH → stake becomes 100 - 20 = 80 ETH
      expect(await registry.getStake(validator1)).to.equal(ethers.parseEther("80"));
    });

    it("should emit ValidatorSlashed event with isMajor=true", async function () {
      const stake = ethers.parseEther("100");
      await registerValidator(validator1, stake);

      const govSigner = (await ethers.getSigners())[0];
      const registryAsGov = registry.connect(govSigner as any);

      await expect(registryAsGov.slashValidatorMajor(validator1))
        .to.emit(registry, "ValidatorSlashed")
        .withArgs(validator1, ethers.parseEther("20"), true);
    });
  });

  // ---------------------------------------------------------------------------
  // Reward distribution
  // ---------------------------------------------------------------------------

  describe("depositRewards", function () {
    it("should accept reward deposits", async function () {
      const signers = await ethers.getSigners();
      const depositor = signers[2];

      const registryAsDepositor = registry.connect(depositor as any);
      await registryAsDepositor.depositRewards({ value: ethers.parseEther("10") });

      expect(await registry.rewardPool()).to.equal(ethers.parseEther("10"));
    });

    it("should revert when deposit is zero", async function () {
      const signers = await ethers.getSigners();
      const depositor = signers[2];

      const registryAsDepositor = registry.connect(depositor as any);
      await expect(
        registryAsDepositor.depositRewards({ value: 0n })
      ).to.be.revertedWith("ValidatorRegistry: zero amount");
    });
  });

  describe("distributeRewards", function () {
    async function registerTwoValidators() {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const v1Signer = signers[1];
      const v2Signer = signers[2];
      const registryAsGov = registry.connect(govSigner as any);

      // Fund validators directly so they can call registerValidator with msg.value
      await govSigner.sendTransaction({
        to: await v1Signer.getAddress(),
        value: ethers.parseEther("250"),
      });
      await govSigner.sendTransaction({
        to: await v2Signer.getAddress(),
        value: ethers.parseEther("150"),
      });

      const dummyKey1 = ("0x" + "aa".repeat(1952)) as `0x${string}`;
      const dummyKey2 = ("0x" + "bb".repeat(1952)) as `0x${string}`;

      // Governance registers validators; each validator sends msg.value with their call
      await registryAsGov.registerValidator(await v1Signer.getAddress(), dummyKey1, {
        value: ethers.parseEther("200"),
      });
      await registryAsGov.registerValidator(await v2Signer.getAddress(), dummyKey2, {
        value: ethers.parseEther("100"),
      });
    }

    it("should distribute rewards proportionally", async function () {
      await registerTwoValidators();

      // Deposit rewards: 30 ETH total
      const signers = await ethers.getSigners();
      await signers[0].sendTransaction({
        to: registry.target,
        value: ethers.parseEther("30"),
      });

      const govSigner = signers[0];
      const registryAsGov = registry.connect(govSigner as any);

      const v1BalanceBefore = await ethers.provider.getBalance(validator1);
      const v2BalanceBefore = await ethers.provider.getBalance(validator2);

      await registryAsGov.distributeRewards();

      const v1BalanceAfter = await ethers.provider.getBalance(validator1);
      const v2BalanceAfter = await ethers.provider.getBalance(validator2);

      // v1 has 200/300 = 2/3 of stake, should get 2/3 of 30 = 20 ETH
      expect(v1BalanceAfter - v1BalanceBefore).to.equal(ethers.parseEther("20"));
      // v2 has 100/300 = 1/3 of stake, should get 1/3 of 30 = 10 ETH
      expect(v2BalanceAfter - v2BalanceBefore).to.equal(ethers.parseEther("10"));
    });

    it("should revert when no active stake", async function () {
      const govSigner = (await ethers.getSigners())[0];
      const registryAsGov = registry.connect(govSigner as any);

      await expect(registryAsGov.distributeRewards()).to.be.revertedWith(
        "ValidatorRegistry: no active stake"
      );
    });

    it("should revert when no rewards in pool", async function () {
      await registerTwoValidators();

      const govSigner = (await ethers.getSigners())[0];
      const registryAsGov = registry.connect(govSigner as any);

      await expect(registryAsGov.distributeRewards()).to.be.revertedWith(
        "ValidatorRegistry: no rewards"
      );
    });
  });

  // ---------------------------------------------------------------------------
  // Governance
  // ---------------------------------------------------------------------------

  describe("setGovernance", function () {
    it("should let governance transfer ownership", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const newGov = signers[3];

      const registryAsGov = registry.connect(govSigner as any);
      await registryAsGov.setGovernance(await newGov.getAddress());

      expect(await registry.governance()).to.equal(await newGov.getAddress());
    });

    it("should emit GovernanceChanged event", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const newGov = signers[3];

      const registryAsGov = registry.connect(govSigner as any);
      await expect(registryAsGov.setGovernance(await newGov.getAddress()))
        .to.emit(registry, "GovernanceChanged")
        .withArgs(await govSigner.getAddress(), await newGov.getAddress());
    });

    it("should revert when non-governance calls setGovernance", async function () {
      const signers = await ethers.getSigners();
      const nonGov = signers[2];

      const registryAsNonGov = registry.connect(nonGov as any);
      await expect(
        registryAsNonGov.setGovernance(await signers[3].getAddress())
      ).to.be.revertedWith("ValidatorRegistry: only governance");
    });
  });

  describe("setValidatorKey", function () {
    async function registerValidator(valAddress: string) {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const registryAsGov = registry.connect(govSigner as any);
      await signers[0].sendTransaction({
        to: registry.target,
        value: ethers.parseEther("200"),
      });
      const dummyKey = ("0x" + "cc".repeat(1952)) as `0x${string}`;
      await registryAsGov.registerValidator(valAddress, dummyKey, {
        value: ethers.parseEther("200"),
      });
    }

    it("should let governance update validator key", async function () {
      await registerValidator(validator1);

      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const registryAsGov = registry.connect(govSigner as any);

      const newKey = ("0x" + "dd".repeat(1952)) as `0x${string}`;
      await registryAsGov.setValidatorKey(validator1, newKey);

      const retrievedKey = await registry.getValidatorKey(validator1);
      expect(retrievedKey).to.equal(newKey);
    });

    it("should emit ValidatorKeyUpdated event", async function () {
      await registerValidator(validator1);

      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const registryAsGov = registry.connect(govSigner as any);

      const newKey = ("0x" + "ee".repeat(1952)) as `0x${string}`;
      await expect(registryAsGov.setValidatorKey(validator1, newKey))
        .to.emit(registry, "ValidatorKeyUpdated")
        .withArgs(validator1, ("0x" + "cc".repeat(1952)) as `0x${string}`, newKey);
    });

    it("should revert when key size is invalid", async function () {
      await registerValidator(validator1);

      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const registryAsGov = registry.connect(govSigner as any);

      const badKey = ("0x" + "ff".repeat(100)) as `0x${string}`;
      await expect(
        registryAsGov.setValidatorKey(validator1, badKey)
      ).to.be.revertedWith("ValidatorRegistry: invalid key size");
    });
  });

  describe("setPaused", function () {
    it("should let governance pause the registry", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const registryAsGov = registry.connect(govSigner as any);

      await registryAsGov.setPaused(true);
      expect(await registry.paused()).to.equal(true);
    });

    it("should emit RegistryPaused event", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const registryAsGov = registry.connect(govSigner as any);

      await expect(registryAsGov.setPaused(true))
        .to.emit(registry, "RegistryPaused")
        .withArgs(true);
    });
  });

  // ---------------------------------------------------------------------------
  // View functions
  // ---------------------------------------------------------------------------

  describe("getActiveValidators", function () {
    it("should return empty array when no validators", async function () {
      const validators = await registry.getActiveValidators();
      expect(validators).to.deep.equal([]);
    });

    it("should return only active validators", async function () {
      const signers = await ethers.getSigners();
      // Use signers[3] for funding since signer[0] (governance) may have low balance
      const funderSigner = signers[3];
      const v1Signer = signers[5];
      const v2Signer = signers[6];
      const registryAsGov = registry.connect(signers[0] as any);

      // Fund validators directly
      await funderSigner.sendTransaction({
        to: await v1Signer.getAddress(),
        value: ethers.parseEther("500"),
      });
      await funderSigner.sendTransaction({
        to: await v2Signer.getAddress(),
        value: ethers.parseEther("300"),
      });

      const dummyKey1 = ("0x" + "11".repeat(1952)) as `0x${string}`;
      const dummyKey2 = ("0x" + "22".repeat(1952)) as `0x${string}`;

      await registryAsGov.registerValidator(await v1Signer.getAddress(), dummyKey1, {
        value: ethers.parseEther("200"),
      });
      await registryAsGov.registerValidator(await v2Signer.getAddress(), dummyKey2, {
        value: ethers.parseEther("100"),
      });

      const validators = await registry.getActiveValidators();
      expect(validators).to.include(await v1Signer.getAddress());
      expect(validators).to.include(await v2Signer.getAddress());
      expect(validators.length).to.equal(2);
    });
  });

  describe("getTotalActiveStake", function () {
    it("should return 0 when no validators", async function () {
      expect(await registry.getTotalActiveStake()).to.equal(0n);
    });
  });

  describe("getValidatorKey", function () {
    it("should return empty bytes for unregistered validator", async function () {
      const key = await registry.getValidatorKey(validator1);
      expect(key).to.equal("0x");
    });
  });
});
