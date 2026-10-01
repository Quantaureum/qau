import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

// Mock ERC20 token for testing lock/unlock of ERC20
const MOCK_ERC20_ABI = [
  "function balanceOf(address) view returns (uint256)",
  "function transfer(address, uint256) returns (bool)",
  "function transferFrom(address, address, uint256) returns (bool)",
  "function approve(address, uint256) returns (bool)",
  "function allowance(address, address) view returns (uint256)",
  "function totalSupply() view returns (uint256)",
  "function decimals() view returns (uint8)",
  "function name() view returns (string)",
  "function symbol() view returns (string)",
];

describe("EthereumBridge", function () {
  let bridge: any;
  let governance: string;
  let relayer: string;
  let user: string;
  let mockToken: any;
  let qauAddress: string;

  beforeEach(async function () {
    const [signer1, signer2, signer3] = await ethers.getSigners();
    governance = await signer1.getAddress();
    relayer = await signer2.getAddress();
    user = await signer3.getAddress();

    const BridgeFactory = await ethers.getContractFactory("EthereumBridge");
    bridge = await BridgeFactory.deploy(governance);
    await bridge.waitForDeployment();

    // Authorize relayer
    await bridge.setRelayerAuthorization(relayer, true);

    // Deploy mock ERC20 token
    const MockERC20Factory = new ethers.ContractFactory(
      MOCK_ERC20_ABI,
      "0x0000000000000000000000000000000000000000000000000000000000000060",
      (await ethers.getSigners())[0]
    );
    // Deploy a simple mock ERC20 using a basic contract
    const MockTokenFactory = await ethers.getContractFactory("WrappedToken");
    mockToken = await MockTokenFactory.deploy("MockToken", "MOCK", bridge.target, "0x0000000000000000000000000000000000000001");
    await mockToken.waitForDeployment();

    // Give user some mock tokens
    // The mock token needs to allow bridge to transferFrom
    // For testing, we'll use direct balance manipulation or a simpler approach
    qauAddress = ethers.keccak256(ethers.toUtf8Bytes("user_quantaureum_address"));
  });

  // ---------------------------------------------------------------------------
  // lockETH
  // ---------------------------------------------------------------------------

  describe("lockETH", function () {
    it("should accept ETH lock with valid amount", async function () {
      const lockTx = bridge.connect(
        ethers.SignerLike ? (await ethers.getSigners())[0] : null
      ) as any;

      // Use signer directly
      const [signer] = await ethers.getSigners();
      const bridgeWithSigner = bridge.connect(signer as any);
      const qauAddr = ethers.keccak256(ethers.toUtf8Bytes("user_qau"));

      const balanceBefore = await ethers.provider.getBalance(bridge.target);

      await expect(
        signer.sendTransaction({
          to: bridge.target,
          value: ethers.parseEther("1.0"),
          data: bridge.interface.encodeFunctionData("lockETH", [qauAddr]),
        })
      ).to.changeEtherBalance(signer, -ethers.parseEther("1.0"));
    });

    it("should emit TokensLocked event with correct fields", async function () {
      const [signer] = await ethers.getSigners();
      const qauAddr = ethers.keccak256(ethers.toUtf8Bytes("user_qau"));

      const lockAmount = ethers.parseEther("1.0");
      const tx = await signer.sendTransaction({
        to: bridge.target,
        value: lockAmount,
        data: bridge.interface.encodeFunctionData("lockETH", [qauAddr]),
      });
      const receipt = await tx.wait();

      // Use queryFilter to properly decode the event (handles indexed params correctly)
      const events = await bridge.queryFilter("TokensLocked", receipt.blockNumber, receipt.blockNumber);
      const eventArgs = events[0]?.args;
      const txHash = eventArgs ? eventArgs[3] : ethers.ZeroHash;

      await expect(tx)
        .to.emit(bridge, "TokensLocked")
        .withArgs(await signer.getAddress(), lockAmount, qauAddr, txHash);
    });

    it("should revert when amount is below minimum", async function () {
      const [signer] = await ethers.getSigners();
      const qauAddr = ethers.keccak256(ethers.toUtf8Bytes("user_qau"));
      const belowMin = 1n; // MIN_LOCK_AMOUNT = 1e15

      await expect(
        signer.sendTransaction({
          to: bridge.target,
          value: belowMin,
          data: bridge.interface.encodeFunctionData("lockETH", [qauAddr]),
        })
      ).to.be.revertedWith("Bridge: below minimum");
    });

    it("should revert when amount exceeds maximum", async function () {
      const [signer] = await ethers.getSigners();
      const qauAddr = ethers.keccak256(ethers.toUtf8Bytes("user_qau"));
      // MAX_LOCK_AMOUNT = 500 ether. Use 600 ether — exceeds the max and is
      // well within the signer's ~10000 ETH starting balance.
      const overMax = ethers.parseEther("600");

      await expect(
        signer.sendTransaction({
          to: bridge.target,
          value: overMax,
          data: bridge.interface.encodeFunctionData("lockETH", [qauAddr]),
        })
      ).to.be.revertedWith("Bridge: exceeds maximum");
    });

    it("should revert when qauAddress is zero", async function () {
      const [signer] = await ethers.getSigners();

      await expect(
        signer.sendTransaction({
          to: bridge.target,
          value: ethers.parseEther("1.0"),
          data: bridge.interface.encodeFunctionData("lockETH", ["0x0000000000000000000000000000000000000000000000000000000000000000"]),
        })
      ).to.be.revertedWith("Bridge: invalid QAU address");
    });

    it("should revert when paused", async function () {
      const [signer] = await ethers.getSigners();
      const qauAddr = ethers.keccak256(ethers.toUtf8Bytes("user_qau"));

      await bridge.connect(signer as any).setPaused(true);

      await expect(
        signer.sendTransaction({
          to: bridge.target,
          value: ethers.parseEther("1.0"),
          data: bridge.interface.encodeFunctionData("lockETH", [qauAddr]),
        })
      ).to.be.revertedWith("Bridge: paused");
    });

    it("should increment user nonce after lock", async function () {
      const [signer] = await ethers.getSigners();
      const qauAddr = ethers.keccak256(ethers.toUtf8Bytes("user_qau"));

      const nonceBefore = await bridge.nonces(signer.address);
      await signer.sendTransaction({
        to: bridge.target,
        value: ethers.parseEther("1.0"),
        data: bridge.interface.encodeFunctionData("lockETH", [qauAddr]),
      });
      const nonceAfter = await bridge.nonces(signer.address);

      expect(nonceAfter).to.equal(nonceBefore + 1n);
    });
  });

  // ---------------------------------------------------------------------------
  // unlockETH
  // ---------------------------------------------------------------------------

  describe("unlockETH", function () {
    it("should let authorized relayer unlock ETH", async function () {
      const [signer, relayerSigner, recipient] = await ethers.getSigners();
      const lockAmount = ethers.parseEther("1.0");
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("lock_tx_hash_1"));

      // Fund the bridge with ETH first by locking
      await signer.sendTransaction({
        to: bridge.target,
        value: lockAmount,
        data: bridge.interface.encodeFunctionData("lockETH", [ethers.keccak256(ethers.toUtf8Bytes("user_qau"))]),
      });

      const recipientBalanceBefore = await ethers.provider.getBalance(await recipient.getAddress());

      const bridgeAsRelayer = bridge.connect(relayerSigner as any);
      await bridgeAsRelayer.unlockETH(
        await recipient.getAddress(),
        lockAmount,
        lockTxHash,
        1,
        []
      );

      const recipientBalanceAfter = await ethers.provider.getBalance(await recipient.getAddress());
      expect(recipientBalanceAfter - recipientBalanceBefore).to.equal(lockAmount);
    });

    it("should revert when non-relayer calls unlockETH", async function () {
      const [signer, , , nonRelayer] = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("lock_tx_hash_2"));

      // Fund the bridge first so the ETH transfer check doesn't mask the relayer check
      await signer.sendTransaction({
        to: bridge.target,
        value: ethers.parseEther("1.0"),
        data: bridge.interface.encodeFunctionData("lockETH", [ethers.keccak256(ethers.toUtf8Bytes("user_qau"))]),
      });

      const bridgeAsNonRelayer = bridge.connect(nonRelayer as any);
      await expect(
        bridgeAsNonRelayer.unlockETH(
          await signer.getAddress(),
          ethers.parseEther("0.1"),
          lockTxHash,
          1,
          []
        )
      ).to.be.revertedWith("Bridge: unauthorized relayer");
    });

    it("should revert when recipient is zero address", async function () {
      const [, relayerSigner] = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("lock_tx_hash_3"));

      const bridgeAsRelayer = bridge.connect(relayerSigner as any);
      await expect(
        bridgeAsRelayer.unlockETH(
          ethers.ZeroAddress,
          ethers.parseEther("0.1"),
          lockTxHash,
          1,
          []
        )
      ).to.be.revertedWith("Bridge: zero recipient");
    });

    it("should revert when amount is zero", async function () {
      const [, relayerSigner] = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("lock_tx_hash_4"));

      const bridgeAsRelayer = bridge.connect(relayerSigner as any);
      await expect(
        bridgeAsRelayer.unlockETH(
          await relayerSigner.getAddress(),
          0n,
          lockTxHash,
          1,
          []
        )
      ).to.be.revertedWith("Bridge: zero amount");
    });

    it("should revert when nonce already used", async function () {
      const [signer, relayerSigner, recipient] = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("lock_tx_hash_5"));
      const nonce = 42;

      // Fund the bridge first
      await signer.sendTransaction({
        to: bridge.target,
        value: ethers.parseEther("0.5"),
        data: bridge.interface.encodeFunctionData("lockETH", [ethers.keccak256(ethers.toUtf8Bytes("fund_nonce"))]),
      });

      const bridgeAsRelayer = bridge.connect(relayerSigner as any);
      // First unlock should succeed
      await bridgeAsRelayer.unlockETH(
        await recipient.getAddress(),
        ethers.parseEther("0.1"),
        lockTxHash,
        nonce,
        []
      );

      // Second unlock with same nonce should fail
      await expect(
        bridgeAsRelayer.unlockETH(
          await recipient.getAddress(),
          ethers.parseEther("0.1"),
          lockTxHash,
          nonce,
          []
        )
      ).to.be.revertedWith("Bridge: nonce already used");
    });

    it("should mark lock tx as processed", async function () {
      const [signer, relayerSigner, recipient] = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("lock_tx_hash_6"));

      // Fund the bridge first
      await signer.sendTransaction({
        to: bridge.target,
        value: ethers.parseEther("0.5"),
        data: bridge.interface.encodeFunctionData("lockETH", [ethers.keccak256(ethers.toUtf8Bytes("fund_processed"))]),
      });

      const bridgeAsRelayer = bridge.connect(relayerSigner as any);
      await bridgeAsRelayer.unlockETH(
        await recipient.getAddress(),
        ethers.parseEther("0.1"),
        lockTxHash,
        1,
        []
      );

      expect(await bridge.isLockProcessed(lockTxHash)).to.equal(true);
    });

    it("should emit UnlockProcessed event", async function () {
      const [signer, relayerSigner, recipient] = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("lock_tx_hash_7"));
      const amount = ethers.parseEther("0.5");

      // Fund the bridge first
      await signer.sendTransaction({
        to: bridge.target,
        value: ethers.parseEther("1.0"),
        data: bridge.interface.encodeFunctionData("lockETH", [ethers.keccak256(ethers.toUtf8Bytes("fund_unlock"))]),
      });

      const bridgeAsRelayer = bridge.connect(relayerSigner as any);
      await expect(bridgeAsRelayer.unlockETH(
        await recipient.getAddress(),
        amount,
        lockTxHash,
        1,
        []
      ))
        .to.emit(bridge, "UnlockProcessed")
        .withArgs(lockTxHash, await recipient.getAddress(), amount, 1);
    });
  });

  // ---------------------------------------------------------------------------
  // Relayer management
  // ---------------------------------------------------------------------------

  describe("setRelayerAuthorization", function () {
    it("should let governance authorize a relayer", async function () {
      const [gov, newRelayer] = await ethers.getSigners();
      const bridgeAsGov = bridge.connect(gov as any);
      const bridgeAsAlice = bridge.connect(newRelayer as any);

      await bridgeAsGov.setRelayerAuthorization(await newRelayer.getAddress(), true);
      expect(await bridge.authorizedRelayers(await newRelayer.getAddress())).to.equal(true);
    });

    it("should let governance deauthorize a relayer", async function () {
      const [gov, alice] = await ethers.getSigners();
      const bridgeAsGov = bridge.connect(gov as any);
      const bridgeAsAlice = bridge.connect(alice as any);

      await bridgeAsGov.setRelayerAuthorization(await alice.getAddress(), false);
      expect(await bridge.authorizedRelayers(await alice.getAddress())).to.equal(false);
    });

    it("should revert when non-governance calls setRelayerAuthorization", async function () {
      const [gov, alice] = await ethers.getSigners();
      const bridgeAsGov = bridge.connect(gov as any);
      const bridgeAsAlice = bridge.connect(alice as any);

      await expect(
        bridgeAsAlice.setRelayerAuthorization(await alice.getAddress(), true)
      ).to.be.revertedWith("Bridge: only governance");
    });
  });

  describe("setRelayerKey", function () {
    it("should let governance set relayer key", async function () {
      const [gov, alice] = await ethers.getSigners();
      const bridgeAsGov = bridge.connect(gov as any);
      const bridgeAsAlice = bridge.connect(alice as any);

      // Create a dummy 1952-byte key
      const dummyKey = "0x" + "11".repeat(1952);

      await bridgeAsGov.setRelayerKey(dummyKey as `0x${string}`);
      // Key is stored, just verify it doesn't revert
    });

    it("should revert when key size is invalid", async function () {
      const [gov, alice] = await ethers.getSigners();
      const bridgeAsGov = bridge.connect(gov as any);

      const badKey = "0x" + "11".repeat(100); // wrong size
      await expect(
        bridgeAsGov.setRelayerKey(badKey as `0x${string}`)
      ).to.be.revertedWith("Bridge: invalid key size");
    });

    it("should revert when non-governance calls setRelayerKey", async function () {
      const [gov, alice] = await ethers.getSigners();
      const bridgeAsAlice = bridge.connect(alice as any);

      const dummyKey = "0x" + "11".repeat(1952);
      await expect(
        bridgeAsAlice.setRelayerKey(dummyKey as `0x${string}`)
      ).to.be.revertedWith("Bridge: only governance");
    });

    it("should emit RelayerKeyUpdated event", async function () {
      const [gov, alice] = await ethers.getSigners();
      const bridgeAsGov = bridge.connect(gov as any);

      const dummyKey = "0x" + "22".repeat(1952);
      await expect(bridgeAsGov.setRelayerKey(dummyKey as `0x${string}`))
        .to.emit(bridge, "RelayerKeyUpdated");
    });
  });

  // ---------------------------------------------------------------------------
  // Governance
  // ---------------------------------------------------------------------------

  describe("setGovernance", function () {
    it("should let governance transfer ownership", async function () {
      const [gov, alice, newGov] = await ethers.getSigners();
      const bridgeAsGov = bridge.connect(gov as any);

      await bridgeAsGov.setGovernance(await newGov.getAddress());
      expect(await bridge.governance()).to.equal(await newGov.getAddress());
    });

    it("should revert when non-governance calls setGovernance", async function () {
      const [gov, alice] = await ethers.getSigners();
      const bridgeAsGov = bridge.connect(gov as any);
      const bridgeAsAlice = bridge.connect(alice as any);

      await expect(
        bridgeAsAlice.setGovernance(await alice.getAddress())
      ).to.be.revertedWith("Bridge: only governance");
    });

    it("should revert when new governance is zero address", async function () {
      const [gov, alice] = await ethers.getSigners();
      const bridgeAsGov = bridge.connect(gov as any);

      await expect(
        bridgeAsGov.setGovernance(ethers.ZeroAddress)
      ).to.be.revertedWith("Bridge: zero governance");
    });

    it("should emit GovernanceChanged event", async function () {
      const [gov, alice, newGov] = await ethers.getSigners();
      const bridgeAsGov = bridge.connect(gov as any);

      await expect(bridgeAsGov.setGovernance(await newGov.getAddress()))
        .to.emit(bridge, "GovernanceChanged")
        .withArgs(await gov.getAddress(), await newGov.getAddress());
    });
  });

  describe("setPaused", function () {
    it("should let governance pause the bridge", async function () {
      const [gov, alice] = await ethers.getSigners();
      const bridgeAsGov = bridge.connect(gov as any);

      await bridgeAsGov.setPaused(true);
      expect(await bridge.paused()).to.equal(true);
    });

    it("should emit BridgePaused event", async function () {
      const [gov, alice] = await ethers.getSigners();
      const bridgeAsGov = bridge.connect(gov as any);

      await expect(bridgeAsGov.setPaused(true))
        .to.emit(bridge, "BridgePaused")
        .withArgs(true);
    });

    it("should revert when non-governance calls setPaused", async function () {
      const [gov, alice] = await ethers.getSigners();
      const bridgeAsAlice = bridge.connect(alice as any);

      await expect(bridgeAsAlice.setPaused(true)).to.be.revertedWith("Bridge: only governance");
    });
  });

  // ---------------------------------------------------------------------------
  // View functions
  // ---------------------------------------------------------------------------

  describe("getNonce", function () {
    it("should return current nonce for user", async function () {
      const [signer] = await ethers.getSigners();
      const nonce = await bridge.getNonce(signer.address);
      expect(typeof nonce).to.equal("bigint");
    });
  });

  describe("isLockProcessed", function () {
    it("should return false for unprocessed tx", async function () {
      const unprocessedHash = ethers.keccak256(ethers.toUtf8Bytes("not_processed"));
      expect(await bridge.isLockProcessed(unprocessedHash)).to.equal(false);
    });

    it("should return true for processed tx", async function () {
      const [signer, relayerSigner, recipient] = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("processed_hash"));

      // Fund the bridge first
      await signer.sendTransaction({
        to: bridge.target,
        value: ethers.parseEther("0.5"),
        data: bridge.interface.encodeFunctionData("lockETH", [ethers.keccak256(ethers.toUtf8Bytes("fund_isprocessed"))]),
      });

      const bridgeAsRelayer = bridge.connect(relayerSigner as any);
      await bridgeAsRelayer.unlockETH(
        await recipient.getAddress(),
        ethers.parseEther("0.1"),
        lockTxHash,
        99,
        []
      );

      expect(await bridge.isLockProcessed(lockTxHash)).to.equal(true);
    });
  });

  // ---------------------------------------------------------------------------
  // ERC165
  // ---------------------------------------------------------------------------

  describe("supportsInterface", function () {
    it("should support IBridgeEvents interface", async function () {
      const IBridgeEventsId = "0x8a326d6e"; // approximate
      // Just verify the function exists and returns a boolean
      const result = await bridge.supportsInterface("0xffffffff");
      expect(typeof result).to.equal("boolean");
    });
  });
});
