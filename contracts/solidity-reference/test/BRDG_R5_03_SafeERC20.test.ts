import { expect } from "chai";
import { ethers } from "hardhat";

// BRDG-R5-03 (2026-07-16) regression tests for SafeERC20 fix.
//
// Vulnerability summary: EthereumBridge.lockERC20 / unlockERC20 used a raw `token.call(...)`
// checking only `success`. For tokens returning `false` without reverting, `transferFrom` fails silently
// yet `success==true`, so the bridge believed the tokens arrived and minted/accounted accordingly.
//
// Fix:
//   - added a SafeERC20 library (OpenZeppelin semantics)
//   - lockERC20 uses safeTransferFromWithBalanceCheck (with a fee-on-transfer balance-delta check)
//   - unlockERC20 uses safeTransfer
//   - the lockERC20 event uses the actually received amount (not the requested amount)

describe("BRDG-R5-03 SafeERC20 Fix", function () {
  let bridge: any;
  let governance: any;
  let relayer: any;
  let user: any;
  let qauAddress: string;

  beforeEach(async function () {
    [governance, relayer, user] = await ethers.getSigners();

    const BridgeFactory = await ethers.getContractFactory("EthereumBridge");
    bridge = await BridgeFactory.deploy(await governance.getAddress());
    await bridge.waitForDeployment();

    await bridge.setRelayerAuthorization(await relayer.getAddress(), true);

    qauAddress = ethers.keccak256(ethers.toUtf8Bytes("user_qau_address"));
  });

  describe("lockERC20 with standard ERC20", function () {
    it("should accept ERC20 lock and emit event with correct amount", async function () {
      const TokenFactory = await ethers.getContractFactory("MockFalseReturnERC20");
      const token = await TokenFactory.deploy("Std", "STD", ethers.parseEther("1000"));
      await token.waitForDeployment();

      // Give user tokens and approve bridge
      await token.mint(await user.getAddress(), ethers.parseEther("100"));
      await token.connect(user).approve(await bridge.getAddress(), ethers.parseEther("100"));

      const tx = bridge.connect(user).lockERC20(
        await token.getAddress(),
        ethers.parseEther("100"),
        qauAddress
      );
      await expect(tx).to.emit(bridge, "ERC20Locked").withArgs(
        await token.getAddress(),
        await user.getAddress(),
        ethers.parseEther("100"),
        qauAddress
      );

      // Bridge should hold the tokens
      expect(await token.balanceOf(await bridge.getAddress())).to.equal(ethers.parseEther("100"));
    });
  });

  describe("lockERC20 with false-returning ERC20 (BRDG-R5-03 core fix)", function () {
    it("should revert when transferFrom returns false (insufficient allowance)", async function () {
      const TokenFactory = await ethers.getContractFactory("MockFalseReturnERC20");
      const token = await TokenFactory.deploy("False", "FLS", ethers.parseEther("1000"));
      await token.waitForDeployment();

      // Give user tokens but DON'T approve bridge
      await token.mint(await user.getAddress(), ethers.parseEther("100"));

      // Without SafeERC20, the raw call would set success=true (because the
      // token returns false without reverting), and the bridge would accept
      // the lock without receiving any tokens. With SafeERC20, this must revert.
      await expect(
        bridge.connect(user).lockERC20(
          await token.getAddress(),
          ethers.parseEther("100"),
          qauAddress
        )
      ).to.be.reverted; // SafeERC20 catches the false return
    });

    it("should revert when transferFrom returns false (insufficient balance)", async function () {
      const TokenFactory = await ethers.getContractFactory("MockFalseReturnERC20");
      const token = await TokenFactory.deploy("False", "FLS", ethers.parseEther("1000"));
      await token.waitForDeployment();

      // Give user only 50 tokens but try to lock 100
      await token.mint(await user.getAddress(), ethers.parseEther("50"));
      await token.connect(user).approve(await bridge.getAddress(), ethers.parseEther("100"));

      await expect(
        bridge.connect(user).lockERC20(
          await token.getAddress(),
          ethers.parseEther("100"),
          qauAddress
        )
      ).to.be.reverted;
    });
  });

  describe("lockERC20 with fee-on-transfer ERC20 (BRDG-R5-03 balance-delta fix)", function () {
    it("should emit event with ACTUAL received amount, not requested amount", async function () {
      const FeeTokenFactory = await ethers.getContractFactory("MockFeeOnTransferERC20");
      // 1% fee (100 bps)
      const token = await FeeTokenFactory.deploy("Fee", "FEE", ethers.parseEther("1000"), 100);
      await token.waitForDeployment();

      // Give user tokens and approve bridge
      await token.mint(await user.getAddress(), ethers.parseEther("100"));
      await token.connect(user).approve(await bridge.getAddress(), ethers.parseEther("100"));

      // Lock 100 tokens with 1% fee → bridge receives 99 tokens
      const expectedReceived = ethers.parseEther("99"); // 100 - 1%
      const tx = bridge.connect(user).lockERC20(
        await token.getAddress(),
        ethers.parseEther("100"),
        qauAddress
      );

      // The event MUST emit the actual received amount (99), NOT the requested (100).
      // This prevents the relayer from minting 100 wrapped tokens when only 99 were locked.
      await expect(tx).to.emit(bridge, "ERC20Locked").withArgs(
        await token.getAddress(),
        await user.getAddress(),
        expectedReceived,
        qauAddress
      );

      // Bridge should hold 99 tokens (after 1% fee)
      expect(await token.balanceOf(await bridge.getAddress())).to.equal(expectedReceived);
    });
  });

  describe("unlockERC20 with SafeERC20", function () {
    it("should transfer tokens to recipient on unlock", async function () {
      const TokenFactory = await ethers.getContractFactory("MockFalseReturnERC20");
      const token = await TokenFactory.deploy("Std", "STD", ethers.parseEther("1000"));
      await token.waitForDeployment();

      // Fund the bridge with tokens
      await token.mint(await bridge.getAddress(), ethers.parseEther("100"));

      const recipient = await user.getAddress();
      const amount = ethers.parseEther("50");
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("lock-tx-1"));
      const nonce = 1n;

      // Set up confirmations (BRDG-R5-01: need requiredConfirmations=2)
      const payloadCommitment = await bridge.computePayloadCommitment(
        await bridge.QUANTAUREUM_CHAIN_ID(),
        lockTxHash,
        recipient,
        await token.getAddress(),
        amount,
        nonce
      );

      // Two relayers need to confirm
      const [, relayer1, relayer2] = await ethers.getSigners();
      await bridge.setRelayerAuthorization(await relayer1.getAddress(), true);
      await bridge.setRelayerAuthorization(await relayer2.getAddress(), true);

      await bridge.connect(relayer1).confirmLock(payloadCommitment);
      await bridge.connect(relayer2).confirmLock(payloadCommitment);

      const recipientBalanceBefore = await token.balanceOf(recipient);
      await bridge.connect(relayer1).unlockERC20(
        await token.getAddress(),
        recipient,
        amount,
        lockTxHash,
        nonce,
        []
      );
      const recipientBalanceAfter = await token.balanceOf(recipient);

      expect(recipientBalanceAfter - recipientBalanceBefore).to.equal(amount);
    });
  });
});
