import { expect } from "chai";
import { ethers } from "hardhat";

describe("QuantaureumBridge", function () {
  let bridge: any;
  let wrappedToken: any;
  let governance: string;
  let relayer: string;
  let user: string;
  let deadline: bigint;
  let relayerSigner: any;
  let secondRelayerSigner: any;

  beforeEach(async function () {
    const [signer1, signer2, signer3, signer4] = await ethers.getSigners();
    governance = await signer1.getAddress();
    relayer = await signer2.getAddress();
    user = await signer3.getAddress();
    relayerSigner = signer2;
    secondRelayerSigner = signer4;

    // Deploy QuantaureumBridge
    const BridgeFactory = await ethers.getContractFactory("QuantaureumBridge");
    bridge = await BridgeFactory.deploy(governance);
    await bridge.waitForDeployment();

    // Deploy WrappedToken with bridge as minter/burner
    const TokenFactory = await ethers.getContractFactory("WrappedToken");
    wrappedToken = await TokenFactory.deploy(
      "Wrapped Ether",
      "wETH",
      bridge.target,
      "0x0000000000000000000000000000000000000001"
    );
    await wrappedToken.waitForDeployment();

    // Register the token in the bridge
    await bridge.setRelayerAuthorization(relayer, true);
    // Register a second relayer so we can reach requiredConfirmations=2
    await bridge.setRelayerAuthorization(secondRelayerSigner.address, true);

    // Register the wrapped token
    await bridge.connect(signer1 as any).registerToken(wrappedToken.target, "0x0000000000000000000000000000000000000001");

    // BRDG-R6-01/02: set wrappedETHToken so mintWrappedETH/burnWrappedETH work.
    // mintWrappedETH looks up wrappedETHToken and requires it to be registered.
    await bridge.connect(signer1 as any).setWrappedETHToken(wrappedToken.target);

    // Set a large deadline (far in the future)
    deadline = BigInt(Math.floor(Date.now() / 1000)) + 86400n * 365n * 100n; // 100 years
  });

  /// BRDG-R5-01 helper: compute the on-chain payload commitment matching
  /// QuantaureumBridge._computePayloadCommitment. MUST be kept in sync with
  /// the contract's keccak256(abi.encode(...)) encoding.
  async function computePayloadCommitment(
    sourceChainId: bigint,
    lockTxHash: string,
    recipient: string,
    token: string,
    amount: bigint,
    nonce: bigint
  ): Promise<string> {
    return ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "bytes32", "address", "address", "uint256", "uint64"],
        [sourceChainId, lockTxHash, recipient, token, amount, nonce]
      )
    );
  }

  /// BRDG-R5-01 helper: have both relayers confirm the payload commitment,
  /// reaching the requiredConfirmations=2 threshold. Then mintWrappedToken
  /// can succeed because it recomputes the same commitment from its args.
  async function confirmPayload(commitment: string) {
    await bridge.connect(relayerSigner).confirmLock(commitment);
    await bridge.connect(secondRelayerSigner).confirmLock(commitment);
  }

  /// BRDG-R5-01 helper: confirm + mint in one step. Computes the commitment
  /// from the exact mint args, gets 2 relayers to attest to it, then mints.
  async function confirmAndMint(
    recipient: string,
    token: string,
    amount: bigint,
    lockTxHash: string,
    nonce: bigint,
    dl: bigint,
    maxAmount: bigint
  ) {
    const commitment = await computePayloadCommitment(
      1n, // ETHEREUM_CHAIN_ID
      lockTxHash,
      recipient,
      token,
      amount,
      nonce
    );
    await confirmPayload(commitment);
    await bridge.connect(relayerSigner).mintWrappedToken(
      recipient,
      token,
      amount,
      lockTxHash,
      nonce,
      dl,
      maxAmount
    );
  }

  /// BRDG-R6-01/02 helper: confirm + mint wrapped ETH in one step. Computes
  /// the commitment from the exact mint args (with token=address(0) sentinel
  /// for native ETH, matching _computePayloadCommitment in mintWrappedETH),
  /// gets 2 relayers to attest to it, then mints wETH.
  async function confirmAndMintETH(
    recipient: string,
    amount: bigint,
    lockTxHash: string,
    nonce: bigint,
    dl: bigint
  ) {
    const commitment = await computePayloadCommitment(
      1n, // ETHEREUM_CHAIN_ID
      lockTxHash,
      recipient,
      ethers.ZeroAddress, // address(0) sentinel for native ETH
      amount,
      nonce
    );
    await confirmPayload(commitment);
    await bridge.connect(relayerSigner).mintWrappedETH(
      recipient,
      amount,
      lockTxHash,
      nonce,
      dl
    );
  }

  // ---------------------------------------------------------------------------
  // mintWrappedToken
  // ---------------------------------------------------------------------------

  describe("mintWrappedToken", function () {
    it("should let authorized relayer mint wrapped tokens", async function () {
      const [, , userSigner] = await ethers.getSigners();
      const mintAmount = ethers.parseEther("1.0");
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("lock_tx"));
      const nonce = 1n;

      await confirmAndMint(
        await userSigner.getAddress(),
        wrappedToken.target,
        mintAmount,
        lockTxHash,
        nonce,
        deadline,
        mintAmount
      );

      expect(await wrappedToken.balanceOf(await userSigner.getAddress())).to.equal(mintAmount);
    });

    it("should revert when non-relayer calls mintWrappedToken", async function () {
      const signers = await ethers.getSigners();
      const nonRelayer = signers[2];
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("lock_tx_nr"));

      const bridgeAsNonRelayer = bridge.connect(nonRelayer as any);
      await expect(
        bridgeAsNonRelayer.mintWrappedToken(
          await nonRelayer.getAddress(),
          wrappedToken.target,
          ethers.parseEther("1.0"),
          lockTxHash,
          1,
          deadline,
          ethers.parseEther("1.0")
        )
      ).to.be.revertedWith("Bridge: unauthorized relayer");
    });

    it("should revert when token is not registered", async function () {
      const signers = await ethers.getSigners();
      const bridgeAsRel = bridge.connect(relayerSigner as any);
      const unregisteredToken = "0x1234567890123456789012345678901234567890";
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("lock_tx_ur"));

      await expect(
        bridgeAsRel.mintWrappedToken(
          await signers[2].getAddress(),
          unregisteredToken,
          ethers.parseEther("1.0"),
          lockTxHash,
          1,
          deadline,
          ethers.parseEther("1.0")
        )
      ).to.be.revertedWith("Bridge: unregistered token");
    });

    it("should revert when amount exceeds maxAmount", async function () {
      const signers = await ethers.getSigners();
      const bridgeAsRel = bridge.connect(relayerSigner as any);
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("lock_tx_ma"));

      await expect(
        bridgeAsRel.mintWrappedToken(
          await signers[2].getAddress(),
          wrappedToken.target,
          ethers.parseEther("2.0"),
          lockTxHash,
          1,
          deadline,
          ethers.parseEther("1.0") // maxAmount is smaller
        )
      ).to.be.revertedWith("Bridge: exceeds maxAmount");
    });

    it("should revert when deadline has passed", async function () {
      const signers = await ethers.getSigners();
      const bridgeAsRel = bridge.connect(relayerSigner as any);
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("lock_tx_dp"));

      const pastDeadline = 1n; // in the past

      await expect(
        bridgeAsRel.mintWrappedToken(
          await signers[2].getAddress(),
          wrappedToken.target,
          ethers.parseEther("1.0"),
          lockTxHash,
          1,
          pastDeadline,
          ethers.parseEther("1.0")
        )
      ).to.be.revertedWith("Bridge: deadline passed");
    });

    it("should revert when lockTxHash already processed", async function () {
      const signers = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("double_mint"));

      // First mint should succeed
      await confirmAndMint(
        await signers[2].getAddress(),
        wrappedToken.target,
        ethers.parseEther("1.0"),
        lockTxHash,
        1n,
        deadline,
        ethers.parseEther("1.0")
      );

      // Second mint with same payload commitment should fail.
      // Use secondRelayerSigner to avoid "nonce already used" (nonce is keyed
      // by keccak256(relayer, nonce), so a different relayer with the same
      // nonce is a fresh key). This lets the test reach the "already processed"
      // check, which is the actual replay-protection mechanism for the payload.
      await expect(
        bridge.connect(secondRelayerSigner).mintWrappedToken(
          await signers[2].getAddress(),
          wrappedToken.target,
          ethers.parseEther("1.0"),
          lockTxHash,
          1n,
          deadline,
          ethers.parseEther("1.0")
        )
      ).to.be.revertedWith("Bridge: already processed");
    });

    it("should emit MintProcessed event", async function () {
      const signers = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("mint_event_test"));
      const mintAmount = ethers.parseEther("0.5");
      const nonce = 17n;

      // Confirm the payload commitment first
      const commitment = await computePayloadCommitment(
        1n,
        lockTxHash,
        await signers[2].getAddress(),
        wrappedToken.target,
        mintAmount,
        nonce
      );
      await confirmPayload(commitment);

      await expect(
        bridge.connect(relayerSigner).mintWrappedToken(
          await signers[2].getAddress(),
          wrappedToken.target,
          mintAmount,
          lockTxHash,
          nonce,
          deadline,
          mintAmount
        )
      )
        .to.emit(bridge, "MintProcessed")
        .withArgs(lockTxHash, await signers[2].getAddress(), wrappedToken.target, mintAmount, nonce);
    });

    // ===========================================================================
    // BRDG-R5-01 security test: payload binding prevents unlimited mint / drain
    // ===========================================================================
    it("BRDG-R5-01: should reject mint with different amount than confirmed payload", async function () {
      const signers = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("r5_01_amount"));

      // Relayers confirm a SMALL payload (1.0 ETH)
      const smallAmount = ethers.parseEther("1.0");
      const commitment = await computePayloadCommitment(
        1n,
        lockTxHash,
        await signers[2].getAddress(),
        wrappedToken.target,
        smallAmount,
        1n
      );
      await confirmPayload(commitment);

      // Attacker tries to mint a LARGE amount (1,000,000 ETH) reusing the same
      // lockTxHash but different amount. Before BRDG-R5-01 fix, the contract
      // only checked lockConfirmations[lockTxHash] >= 2, so this would succeed.
      // After the fix, the commitment is recomputed from the mint args and
      // won't match the confirmed commitment → revert.
      await expect(
        bridge.connect(relayerSigner).mintWrappedToken(
          await signers[2].getAddress(),
          wrappedToken.target,
          ethers.parseEther("1000000.0"), // different amount
          lockTxHash,
          1n,
          deadline,
          ethers.parseEther("1000000.0")
        )
      ).to.be.revertedWith("Bridge: insufficient confirmations");
    });

    it("BRDG-R5-01: should reject mint with different recipient than confirmed payload", async function () {
      const signers = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("r5_01_recipient"));
      const mintAmount = ethers.parseEther("1.0");

      // Relayers confirm payload to legitimate recipient (signers[2])
      const commitment = await computePayloadCommitment(
        1n,
        lockTxHash,
        await signers[2].getAddress(),
        wrappedToken.target,
        mintAmount,
        1n
      );
      await confirmPayload(commitment);

      // Attacker tries to mint to a DIFFERENT recipient (signers[3])
      await expect(
        bridge.connect(relayerSigner).mintWrappedToken(
          await signers[3].getAddress(), // different recipient
          wrappedToken.target,
          mintAmount,
          lockTxHash,
          1n,
          deadline,
          mintAmount
        )
      ).to.be.revertedWith("Bridge: insufficient confirmations");
    });

    it("BRDG-R5-01: should reject mint with different token than confirmed payload", async function () {
      const signers = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("r5_01_token"));
      const mintAmount = ethers.parseEther("1.0");

      // Deploy a second wrapped token and register it
      const TokenFactory = await ethers.getContractFactory("WrappedToken");
      const secondToken = await TokenFactory.deploy("Other", "OTH", bridge.target, "0x0000000000000000000000000000000000000002");
      await secondToken.waitForDeployment();
      await bridge.registerToken(secondToken.target, "0x0000000000000000000000000000000000000002");

      // Relayers confirm payload for wrappedToken
      const commitment = await computePayloadCommitment(
        1n,
        lockTxHash,
        await signers[2].getAddress(),
        wrappedToken.target,
        mintAmount,
        1n
      );
      await confirmPayload(commitment);

      // Attacker tries to mint a DIFFERENT token reusing the same lockTxHash
      await expect(
        bridge.connect(relayerSigner).mintWrappedToken(
          await signers[2].getAddress(),
          secondToken.target, // different token
          mintAmount,
          lockTxHash,
          1n,
          deadline,
          mintAmount
        )
      ).to.be.revertedWith("Bridge: insufficient confirmations");
    });
  });

  // ---------------------------------------------------------------------------
  // mintWrappedETH
  // BRDG-R6-01/02 closure: verifies that QuantaureumBridge.mintWrappedETH
  // uses the same payloadCommitment binding as mintWrappedToken and as
  // EthereumBridge.unlockETH. The audit flagged this path as "needs verification"
  // (needs verification) — these tests provide that verification.
  // ---------------------------------------------------------------------------

  describe("mintWrappedETH", function () {
    it("should let authorized relayer mint wrapped ETH after 2 confirmations", async function () {
      const signers = await ethers.getSigners();
      const userSigner = signers[2];
      const mintAmount = ethers.parseEther("1.0");
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("eth_lock_tx"));

      await confirmAndMintETH(
        await userSigner.getAddress(),
        mintAmount,
        lockTxHash,
        1n,
        deadline
      );

      expect(await wrappedToken.balanceOf(await userSigner.getAddress())).to.equal(mintAmount);
    });

    it("should revert when non-relayer calls mintWrappedETH", async function () {
      const signers = await ethers.getSigners();
      const nonRelayer = signers[2];
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("eth_lock_nr"));

      const bridgeAsNonRelayer = bridge.connect(nonRelayer as any);
      await expect(
        bridgeAsNonRelayer.mintWrappedETH(
          await nonRelayer.getAddress(),
          ethers.parseEther("1.0"),
          lockTxHash,
          1n,
          deadline
        )
      ).to.be.revertedWith("Bridge: unauthorized relayer");
    });

    it("should revert when deadline has passed", async function () {
      const signers = await ethers.getSigners();
      const bridgeAsRel = bridge.connect(relayerSigner as any);
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("eth_lock_dp"));
      const pastDeadline = 1n;

      await expect(
        bridgeAsRel.mintWrappedETH(
          await signers[2].getAddress(),
          ethers.parseEther("1.0"),
          lockTxHash,
          1n,
          pastDeadline
        )
      ).to.be.revertedWith("Bridge: deadline passed");
    });

    it("should revert when same payload commitment already processed", async function () {
      const signers = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("eth_double_mint"));
      const mintAmount = ethers.parseEther("1.0");

      // First mint should succeed
      await confirmAndMintETH(
        await signers[2].getAddress(),
        mintAmount,
        lockTxHash,
        1n,
        deadline
      );

      // Second mint with same payload commitment should fail.
      // Use secondRelayerSigner to avoid "nonce already used" (nonce is keyed
      // by keccak256(relayer, nonce), so a different relayer with the same
      // nonce is a fresh key). This lets the test reach the "already processed"
      // check, which is the actual replay-protection mechanism for the payload.
      await expect(
        bridge.connect(secondRelayerSigner).mintWrappedETH(
          await signers[2].getAddress(),
          mintAmount,
          lockTxHash,
          1n,
          deadline
        )
      ).to.be.revertedWith("Bridge: already processed");
    });

    // ===========================================================================
    // BRDG-R6-01 security tests: payload binding prevents unlimited mint / drain
    // Mirrors the BRDG-R5-01 tests for mintWrappedToken, but for mintWrappedETH.
    // Verifies the QuantaureumBridge.mintWrappedETH path is synchronized with
    // EthereumBridge.unlockETH (both use payloadCommitment with token=address(0)).
    // ===========================================================================
    it("BRDG-R6-01: should reject mint ETH with different amount than confirmed payload", async function () {
      const signers = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("r6_01_eth_amount"));

      // Relayers confirm a SMALL payload (1.0 ETH)
      const smallAmount = ethers.parseEther("1.0");
      const commitment = await computePayloadCommitment(
        1n,
        lockTxHash,
        await signers[2].getAddress(),
        ethers.ZeroAddress, // native ETH sentinel
        smallAmount,
        1n
      );
      await confirmPayload(commitment);

      // Attacker tries to mint a LARGE amount reusing the same lockTxHash.
      // Before payload binding, this would succeed. After BRDG-R6-01
      // verification, the recomputed commitment won't match → revert.
      await expect(
        bridge.connect(relayerSigner).mintWrappedETH(
          await signers[2].getAddress(),
          ethers.parseEther("1000000.0"), // different amount
          lockTxHash,
          1n,
          deadline
        )
      ).to.be.revertedWith("Bridge: insufficient confirmations");
    });

    it("BRDG-R6-01: should reject mint ETH with different recipient than confirmed payload", async function () {
      const signers = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("r6_01_eth_recipient"));
      const mintAmount = ethers.parseEther("1.0");

      // Relayers confirm payload to legitimate recipient (signers[2])
      const commitment = await computePayloadCommitment(
        1n,
        lockTxHash,
        await signers[2].getAddress(),
        ethers.ZeroAddress,
        mintAmount,
        1n
      );
      await confirmPayload(commitment);

      // Attacker tries to mint to a DIFFERENT recipient (signers[3])
      await expect(
        bridge.connect(relayerSigner).mintWrappedETH(
          await signers[3].getAddress(), // different recipient
          mintAmount,
          lockTxHash,
          1n,
          deadline
        )
      ).to.be.revertedWith("Bridge: insufficient confirmations");
    });

    it("BRDG-R6-01: should reject mint ETH with different nonce than confirmed payload", async function () {
      const signers = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("r6_01_eth_nonce"));
      const mintAmount = ethers.parseEther("1.0");

      // Relayers confirm payload with nonce=1
      const commitment = await computePayloadCommitment(
        1n,
        lockTxHash,
        await signers[2].getAddress(),
        ethers.ZeroAddress,
        mintAmount,
        1n
      );
      await confirmPayload(commitment);

      // Attacker tries to mint with nonce=2 reusing the same lockTxHash
      await expect(
        bridge.connect(relayerSigner).mintWrappedETH(
          await signers[2].getAddress(),
          mintAmount,
          lockTxHash,
          2n, // different nonce
          deadline
        )
      ).to.be.revertedWith("Bridge: insufficient confirmations");
    });

    // ===========================================================================
    // BRDG-R6-02: token=address(0) sentinel isolation
    // Verifies that native ETH mints (token=address(0)) and ERC20 mints with
    // a token at address(0) cannot collide. Since address(0) can never be a
    // registered ERC20 token, the sentinel guarantees ETH and ERC20 payload
    // commitments live in disjoint namespaces.
    // ===========================================================================
    it("BRDG-R6-02: ETH payload commitment (token=address(0)) must not satisfy ERC20 mint path", async function () {
      const signers = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("r6_02_sentinel_isolation"));
      const mintAmount = ethers.parseEther("1.0");

      // Relayers confirm ETH payload (token=address(0))
      const ethCommitment = await computePayloadCommitment(
        1n,
        lockTxHash,
        await signers[2].getAddress(),
        ethers.ZeroAddress,
        mintAmount,
        1n
      );
      await confirmPayload(ethCommitment);

      // Attempt to mint ERC20 (wrappedToken) reusing the same lockTxHash.
      // The ERC20 commitment uses wrappedToken.target (not address(0)), so it
      // won't match the ETH confirmation → revert. This proves the address(0)
      // sentinel keeps ETH and ERC20 mint paths in disjoint commitment spaces.
      await expect(
        bridge.connect(relayerSigner).mintWrappedToken(
          await signers[2].getAddress(),
          wrappedToken.target, // ERC20 token, not address(0)
          mintAmount,
          lockTxHash,
          1n,
          deadline,
          mintAmount
        )
      ).to.be.revertedWith("Bridge: insufficient confirmations");
    });

    it("BRDG-R6-02: ERC20 payload commitment must not satisfy ETH mint path", async function () {
      const signers = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("r6_02_sentinel_reverse"));
      const mintAmount = ethers.parseEther("1.0");

      // Relayers confirm ERC20 payload (token=wrappedToken.target)
      const erc20Commitment = await computePayloadCommitment(
        1n,
        lockTxHash,
        await signers[2].getAddress(),
        wrappedToken.target,
        mintAmount,
        1n
      );
      await confirmPayload(erc20Commitment);

      // Attempt to mint ETH reusing the same lockTxHash. The ETH commitment
      // uses address(0) (not wrappedToken.target), so it won't match → revert.
      await expect(
        bridge.connect(relayerSigner).mintWrappedETH(
          await signers[2].getAddress(),
          mintAmount,
          lockTxHash,
          1n,
          deadline
        )
      ).to.be.revertedWith("Bridge: insufficient confirmations");
    });

    it("BRDG-R6-02: should emit MintProcessed event for ETH mint with token=address(0)", async function () {
      const signers = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("eth_mint_event"));
      const mintAmount = ethers.parseEther("0.5");
      const nonce = 42n;

      // Confirm the ETH payload commitment first
      const commitment = await computePayloadCommitment(
        1n,
        lockTxHash,
        await signers[2].getAddress(),
        ethers.ZeroAddress,
        mintAmount,
        nonce
      );
      await confirmPayload(commitment);

      await expect(
        bridge.connect(relayerSigner).mintWrappedETH(
          await signers[2].getAddress(),
          mintAmount,
          lockTxHash,
          nonce,
          deadline
        )
      )
        .to.emit(bridge, "MintProcessed")
        .withArgs(lockTxHash, await signers[2].getAddress(), ethers.ZeroAddress, mintAmount, nonce);
    });
  });

  // ---------------------------------------------------------------------------
  // BRDG-R6-01/02: cross-contract payloadCommitment synchronization
  // Verifies that QuantaureumBridge and EthereumBridge compute IDENTICAL
  // payloadCommitment values for the same inputs, proving the two contracts
  // are synchronized. This closes the audit's "needs verification"
  // concern by demonstrating byte-for-byte equivalence on-chain.
  // ---------------------------------------------------------------------------

  describe("BRDG-R6-01/02: cross-contract payloadCommitment synchronization", function () {
    let ethBridge: any;

    beforeEach(async function () {
      // Deploy EthereumBridge for cross-contract comparison
      const EthBridgeFactory = await ethers.getContractFactory("EthereumBridge");
      ethBridge = await EthBridgeFactory.deploy(governance);
      await ethBridge.waitForDeployment();
    });

    it("both contracts compute identical payloadCommitment for ERC20 payload", async function () {
      const signers = await ethers.getSigners();
      const recipient = await signers[2].getAddress();
      const token = wrappedToken.target;
      const amount = ethers.parseEther("1.5");
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("sync_erc20"));
      const nonce = 7n;
      const sourceChainId = 1n; // Ethereum as source

      const qauCommitment = await bridge.computePayloadCommitment(
        sourceChainId,
        lockTxHash,
        recipient,
        token,
        amount,
        nonce
      );
      const ethCommitment = await ethBridge.computePayloadCommitment(
        sourceChainId,
        lockTxHash,
        recipient,
        token,
        amount,
        nonce
      );

      expect(qauCommitment).to.equal(ethCommitment);
    });

    it("both contracts compute identical payloadCommitment for native ETH payload (token=address(0))", async function () {
      const signers = await ethers.getSigners();
      const recipient = await signers[2].getAddress();
      const amount = ethers.parseEther("2.0");
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("sync_eth"));
      const nonce = 9n;
      const sourceChainId = 1n;

      const qauCommitment = await bridge.computePayloadCommitment(
        sourceChainId,
        lockTxHash,
        recipient,
        ethers.ZeroAddress,
        amount,
        nonce
      );
      const ethCommitment = await ethBridge.computePayloadCommitment(
        sourceChainId,
        lockTxHash,
        recipient,
        ethers.ZeroAddress,
        amount,
        nonce
      );

      expect(qauCommitment).to.equal(ethCommitment);
    });

    it("both contracts reject zero payloadCommitment with the same require message", async function () {
      // This is a structural check: confirmLock on both contracts must reject
      // bytes32(0) with the same error message, ensuring consistent behavior.
      const signers = await ethers.getSigners();
      await bridge.setRelayerAuthorization(await signers[1].getAddress(), true);
      await ethBridge.setRelayerAuthorization(await signers[1].getAddress(), true);

      await expect(
        bridge.connect(signers[1]).confirmLock(ethers.ZeroHash)
      ).to.be.revertedWith("Bridge: zero commitment");

      await expect(
        ethBridge.connect(signers[1]).confirmLock(ethers.ZeroHash)
      ).to.be.revertedWith("Bridge: zero commitment");
    });

    it("QuantaureumBridge.mint uses ETHEREUM_CHAIN_ID=1 as sourceChainId (Ethereum is lock source)", async function () {
      // Verifies the sourceChainId semantics: when minting on Quantaureum,
      // the source chain is Ethereum (where the lock happened), so the
      // commitment uses ETHEREUM_CHAIN_ID=1. This MUST match what relayers
      // compute off-chain from the Ethereum lock event.
      const signers = await ethers.getSigners();
      const recipient = await signers[2].getAddress();
      const amount = ethers.parseEther("1.0");
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("source_id_mint"));
      const nonce = 1n;

      // Relayer computes commitment with sourceChainId=1 (Ethereum)
      const relayerCommitment = await computePayloadCommitment(
        1n, // ETHEREUM_CHAIN_ID — Ethereum is the lock source
        lockTxHash,
        recipient,
        wrappedToken.target,
        amount,
        nonce
      );
      await confirmPayload(relayerCommitment);

      // mintWrappedToken recomputes with ETHEREUM_CHAIN_ID internally and
      // must match. If the contract used a different sourceChainId, the
      // recomputed commitment wouldn't match → "insufficient confirmations".
      await expect(
        bridge.connect(relayerSigner).mintWrappedToken(
          recipient,
          wrappedToken.target,
          amount,
          lockTxHash,
          nonce,
          deadline,
          amount
        )
      ).to.not.be.reverted;
    });

    it("EthereumBridge.unlock uses QUANTAUREUM_CHAIN_ID=1669 as sourceChainId (QAU is burn source)", async function () {
      // Verifies the sourceChainId semantics: when unlocking on Ethereum,
      // the source chain is Quantaureum (where the burn happened), so the
      // commitment uses QUANTAUREUM_CHAIN_ID=1669. This MUST match what
      // relayers compute off-chain from the Quantaureum burn event.
      const signers = await ethers.getSigners();
      const recipient = await signers[2].getAddress();
      const amount = ethers.parseEther("1.0");
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("source_id_unlock"));
      const nonce = 1n;

      // Relayer computes commitment with sourceChainId=1669 (Quantaureum)
      const relayerCommitment = await computePayloadCommitment(
        1669n, // QUANTAUREUM_CHAIN_ID — Quantaureum is the burn source
        lockTxHash,
        recipient,
        ethers.ZeroAddress, // native ETH unlock
        amount,
        nonce
      );

      // Authorize relayers on EthereumBridge and confirm
      await ethBridge.setRelayerAuthorization(relayer, true);
      await ethBridge.setRelayerAuthorization(secondRelayerSigner.address, true);
      await ethBridge.connect(relayerSigner).confirmLock(relayerCommitment);
      await ethBridge.connect(secondRelayerSigner).confirmLock(relayerCommitment);

      // unlockETH recomputes with QUANTAUREUM_CHAIN_ID internally and must
      // match. If the contract used a different sourceChainId, the recomputed
      // commitment wouldn't match → "insufficient confirmations".
      // Fund the EthereumBridge with ETH via lockETH (the contract has no
      // receive()/fallback(), so direct sendTransaction would revert).
      await ethBridge.connect(signers[0]).lockETH(
        ethers.keccak256(ethers.toUtf8Bytes("funding_qau_addr")),
        { value: amount }
      );

      await expect(
        ethBridge.connect(relayerSigner).unlockETH(
          recipient,
          amount,
          lockTxHash,
          nonce,
          [] // empty proof (reserved)
        )
      ).to.not.be.reverted;
    });
  });

  // ---------------------------------------------------------------------------
  // burnWrappedToken
  // ---------------------------------------------------------------------------

  describe("burnWrappedToken", function () {
    it("should let user burn wrapped tokens", async function () {
      const signers = await ethers.getSigners();
      const userSigner = signers[2];

      // First mint tokens to user (with payload confirmation)
      const mintAmount = ethers.parseEther("2.0");
      await confirmAndMint(
        await userSigner.getAddress(),
        wrappedToken.target,
        mintAmount,
        ethers.keccak256(ethers.toUtf8Bytes("mint_for_burn")),
        1n,
        deadline,
        mintAmount
      );

      // User burns tokens
      const bridgeAsUser = bridge.connect(userSigner as any);
      const burnAmount = ethers.parseEther("1.0");
      await bridgeAsUser.burnWrappedToken(
        wrappedToken.target,
        burnAmount,
        "0x1234567890123456789012345678901234567890",
        deadline
      );

      expect(await wrappedToken.balanceOf(await userSigner.getAddress())).to.equal(burnAmount);
    });

    it("should revert when paused", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const userSigner = signers[2];

      // Pause the bridge
      await bridge.connect(govSigner as any).setPaused(true);

      const bridgeAsUser = bridge.connect(userSigner as any);
      await expect(
        bridgeAsUser.burnWrappedToken(
          wrappedToken.target,
          ethers.parseEther("1.0"),
          "0x1234567890123456789012345678901234567890",
          deadline
        )
      ).to.be.revertedWith("Bridge: paused");
    });

    it("should revert when deadline passed", async function () {
      const signers = await ethers.getSigners();
      const userSigner = signers[2];

      const bridgeAsUser = bridge.connect(userSigner as any);
      const pastDeadline = 1n;

      await expect(
        bridgeAsUser.burnWrappedToken(
          wrappedToken.target,
          ethers.parseEther("1.0"),
          "0x1234567890123456789012345678901234567890",
          pastDeadline
        )
      ).to.be.revertedWith("Bridge: deadline passed");
    });

    it("should revert when amount is zero", async function () {
      const signers = await ethers.getSigners();
      const userSigner = signers[2];

      const bridgeAsUser = bridge.connect(userSigner as any);
      await expect(
        bridgeAsUser.burnWrappedToken(
          wrappedToken.target,
          0n,
          "0x1234567890123456789012345678901234567890",
          deadline
        )
      ).to.be.revertedWith("Bridge: zero amount");
    });

    it("should emit WrappedTokenBurned event", async function () {
      const signers = await ethers.getSigners();
      const userSigner = signers[2];
      const ethAddress = "0x1234567890123456789012345678901234567890";
      const burnAmount = ethers.parseEther("0.5");

      // Mint first (with payload confirmation)
      await confirmAndMint(
        await userSigner.getAddress(),
        wrappedToken.target,
        burnAmount,
        ethers.keccak256(ethers.toUtf8Bytes("mint_for_burn_event")),
        1n,
        deadline,
        burnAmount
      );

      const bridgeAsUser = bridge.connect(userSigner as any);
      await expect(
        bridgeAsUser.burnWrappedToken(wrappedToken.target, burnAmount, ethAddress, deadline)
      )
        .to.emit(bridge, "WrappedTokenBurned")
        .withArgs(wrappedToken.target, await userSigner.getAddress(), burnAmount, ethAddress);
    });
  });

  // ---------------------------------------------------------------------------
  // burnWrappedETH
  // ---------------------------------------------------------------------------

  describe("burnWrappedETH", function () {
    it("should let user burn wrapped ETH for unlock", async function () {
      const signers = await ethers.getSigners();
      const userSigner = signers[2];

      // Mint wETH to user first so they have a balance to burn
      const mintAmount = ethers.parseEther("1.0");
      await confirmAndMintETH(
        await userSigner.getAddress(),
        mintAmount,
        ethers.keccak256(ethers.toUtf8Bytes("mint_for_eth_burn")),
        1n,
        deadline
      );

      const bridgeAsUser = bridge.connect(userSigner as any);
      const burnAmount = ethers.parseEther("0.5");
      const ethAddress = "0x1234567890123456789012345678901234567890";

      await bridgeAsUser.burnWrappedETH(burnAmount, ethAddress, deadline);
      // Should not revert
    });

    it("should revert when paused", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const userSigner = signers[2];

      await bridge.connect(govSigner as any).setPaused(true);

      const bridgeAsUser = bridge.connect(userSigner as any);
      await expect(
        bridgeAsUser.burnWrappedETH(
          ethers.parseEther("0.5"),
          "0x1234567890123456789012345678901234567890",
          deadline
        )
      ).to.be.revertedWith("Bridge: paused");
    });

    it("should emit TokensBurned event", async function () {
      const signers = await ethers.getSigners();
      const userSigner = signers[2];

      // Mint wETH to user first so they have a balance to burn
      const mintAmount = ethers.parseEther("1.0");
      await confirmAndMintETH(
        await userSigner.getAddress(),
        mintAmount,
        ethers.keccak256(ethers.toUtf8Bytes("mint_for_eth_burn_event")),
        1n,
        deadline
      );

      const bridgeAsUser = bridge.connect(userSigner as any);
      const burnAmount = ethers.parseEther("0.3");
      const ethAddress = "0x1234567890123456789012345678901234567890";

      await expect(bridgeAsUser.burnWrappedETH(burnAmount, ethAddress, deadline))
        .to.emit(bridge, "TokensBurned")
        .withArgs(await userSigner.getAddress(), burnAmount, ethAddress, ethers.ZeroHash);
    });
  });

  // ---------------------------------------------------------------------------
  // Token registration
  // ---------------------------------------------------------------------------

  describe("registerToken", function () {
    it("should let governance register a token", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];

      const TokenFactory = await ethers.getContractFactory("WrappedToken");
      const newToken = await TokenFactory.deploy("NewToken", "NT", bridge.target, "0x0000000000000000000000000000000000000002");
      await newToken.waitForDeployment();

      const underlying = "0x1111111111111111111111111111111111111111";
      await bridge.connect(govSigner as any).registerToken(newToken.target, underlying);

      expect(await bridge.isTokenRegistered(newToken.target)).to.equal(true);
    });

    it("should revert when non-governance registers a token", async function () {
      const signers = await ethers.getSigners();
      const nonGov = signers[2];

      const TokenFactory = await ethers.getContractFactory("WrappedToken");
      const newToken = await TokenFactory.deploy("NewToken", "NT", bridge.target, "0x0000000000000000000000000000000000000003");
      await newToken.waitForDeployment();

      const bridgeAsNonGov = bridge.connect(nonGov as any);
      const underlying = "0x3333333333333333333333333333333333333333";
      await expect(
        bridgeAsNonGov.registerToken(newToken.target, underlying)
      ).to.be.revertedWith("Bridge: only governance");
    });

    it("should revert when token is zero address", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];

      const bridgeAsGov = bridge.connect(govSigner as any);
      const underlying = "0x4444444444444444444444444444444444444444";
      await expect(
        bridgeAsGov.registerToken(ethers.ZeroAddress, underlying)
      ).to.be.revertedWith("Bridge: zero token");
    });

    it("should emit TokenRegistered event", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];

      const TokenFactory = await ethers.getContractFactory("WrappedToken");
      const newToken = await TokenFactory.deploy("NewToken", "NT", bridge.target, "0x0000000000000000000000000000000000000004");
      await newToken.waitForDeployment();

      const underlying = "0x2222222222222222222222222222222222222222";
      const bridgeAsGov = bridge.connect(govSigner as any);

      await expect(bridgeAsGov.registerToken(newToken.target, underlying))
        .to.emit(bridge, "TokenRegistered")
        .withArgs(newToken.target, underlying);
    });
  });

  // ---------------------------------------------------------------------------
  // Relayer management
  // ---------------------------------------------------------------------------

  describe("setRelayerAuthorization", function () {
    it("should let governance authorize a relayer", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const newRelayer = signers[3];

      const bridgeAsGov = bridge.connect(govSigner as any);
      await bridgeAsGov.setRelayerAuthorization(await newRelayer.getAddress(), true);

      expect(await bridge.authorizedRelayers(await newRelayer.getAddress())).to.equal(true);
    });

    it("should revert when non-governance calls setRelayerAuthorization", async function () {
      const signers = await ethers.getSigners();
      const nonGov = signers[2];

      const bridgeAsNonGov = bridge.connect(nonGov as any);
      await expect(
        bridgeAsNonGov.setRelayerAuthorization(await nonGov.getAddress(), true)
      ).to.be.revertedWith("Bridge: only governance");
    });
  });

  // ---------------------------------------------------------------------------
  // BRDG-R5-06: relayer consensus must be on the SAME payload
  // ---------------------------------------------------------------------------

  describe("BRDG-R5-06: same-payload consensus", function () {
    /// BRDG-R5-06 (2026-07-16): confirmLock counts attestations per
    /// payloadCommitment (not per lockTxHash). Two relayers who witness
    /// DIFFERENT facts (different amount/recipient/token/nonce) must NOT
    /// reach the quorum on either payload. This is the "same-payload
    /// consensus constraint" that BRDG-R5-06 calls out as a latent risk
    /// when the counter key is the bare lockTxHash. With payloadCommitment
    /// as the key (BRDG-R5-01 fix), the constraint is enforced structurally.

    it("BRDG-R5-06: two relayers witnessing different amounts must not reach quorum on either", async function () {
      const signers = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("r5_06_split_amount"));
      const recipient = await signers[2].getAddress();
      const nonce = 1n;

      // Relayer A attests to amount = 1.0
      const commitmentA = await computePayloadCommitment(
        1n,
        lockTxHash,
        recipient,
        wrappedToken.target,
        ethers.parseEther("1.0"),
        nonce
      );
      await bridge.connect(relayerSigner).confirmLock(commitmentA);

      // Relayer B attests to amount = 2.0 (different fact)
      const commitmentB = await computePayloadCommitment(
        1n,
        lockTxHash,
        recipient,
        wrappedToken.target,
        ethers.parseEther("2.0"),
        nonce
      );
      await bridge.connect(secondRelayerSigner).confirmLock(commitmentB);

      // Neither payload reaches requiredConfirmations=2.
      // Attempting to mint 1.0 fails (only 1 confirmation on commitmentA).
      await expect(
        bridge.connect(relayerSigner).mintWrappedToken(
          recipient,
          wrappedToken.target,
          ethers.parseEther("1.0"),
          lockTxHash,
          nonce,
          deadline,
          ethers.parseEther("1.0")
        )
      ).to.be.revertedWith("Bridge: insufficient confirmations");

      // Attempting to mint 2.0 also fails (only 1 confirmation on commitmentB).
      await expect(
        bridge.connect(relayerSigner).mintWrappedToken(
          recipient,
          wrappedToken.target,
          ethers.parseEther("2.0"),
          lockTxHash,
          nonce,
          deadline,
          ethers.parseEther("2.0")
        )
      ).to.be.revertedWith("Bridge: insufficient confirmations");
    });

    it("BRDG-R5-06: two relayers witnessing different recipients must not reach quorum on either", async function () {
      const signers = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("r5_06_split_recipient"));
      const mintAmount = ethers.parseEther("1.0");
      const nonce = 1n;

      const recipientA = await signers[2].getAddress();
      const recipientB = await signers[3].getAddress();

      // Relayer A attests to recipientA
      const commitmentA = await computePayloadCommitment(
        1n,
        lockTxHash,
        recipientA,
        wrappedToken.target,
        mintAmount,
        nonce
      );
      await bridge.connect(relayerSigner).confirmLock(commitmentA);

      // Relayer B attests to recipientB (different fact)
      const commitmentB = await computePayloadCommitment(
        1n,
        lockTxHash,
        recipientB,
        wrappedToken.target,
        mintAmount,
        nonce
      );
      await bridge.connect(secondRelayerSigner).confirmLock(commitmentB);

      // Neither recipient reaches quorum.
      await expect(
        bridge.connect(relayerSigner).mintWrappedToken(
          recipientA,
          wrappedToken.target,
          mintAmount,
          lockTxHash,
          nonce,
          deadline,
          mintAmount
        )
      ).to.be.revertedWith("Bridge: insufficient confirmations");

      await expect(
        bridge.connect(relayerSigner).mintWrappedToken(
          recipientB,
          wrappedToken.target,
          mintAmount,
          lockTxHash,
          nonce,
          deadline,
          mintAmount
        )
      ).to.be.revertedWith("Bridge: insufficient confirmations");
    });

    it("BRDG-R5-06: same-payload attestations from two relayers DO reach quorum (control)", async function () {
      // Control test: when both relayers attest to the SAME payload,
      // quorum IS reached and mint succeeds. This confirms the fix doesn't
      // break the legitimate path.
      const signers = await ethers.getSigners();
      const lockTxHash = ethers.keccak256(ethers.toUtf8Bytes("r5_06_same"));
      const recipient = await signers[2].getAddress();
      const mintAmount = ethers.parseEther("1.0");
      const nonce = 1n;

      // Both relayers attest to the SAME payload
      const commitment = await computePayloadCommitment(
        1n,
        lockTxHash,
        recipient,
        wrappedToken.target,
        mintAmount,
        nonce
      );
      await bridge.connect(relayerSigner).confirmLock(commitment);
      await bridge.connect(secondRelayerSigner).confirmLock(commitment);

      // Quorum reached → mint succeeds
      await bridge.connect(relayerSigner).mintWrappedToken(
        recipient,
        wrappedToken.target,
        mintAmount,
        lockTxHash,
        nonce,
        deadline,
        mintAmount
      );

      expect(await wrappedToken.balanceOf(recipient)).to.equal(mintAmount);
    });
  });

  // ---------------------------------------------------------------------------
  // Validator key management
  // ---------------------------------------------------------------------------

  describe("setValidatorKey", function () {
    it("should let governance set validator key", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const validator = signers[3];

      const bridgeAsGov = bridge.connect(govSigner as any);
      const dummyKey = "0x" + "33".repeat(1952);

      await bridgeAsGov.setValidatorKey(await validator.getAddress(), dummyKey as `0x${string}`);
      // Key is stored - just verify no revert
    });

    it("should revert when key size is invalid", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];

      const bridgeAsGov = bridge.connect(govSigner as any);
      const badKey = "0x" + "33".repeat(100);

      await expect(
        bridgeAsGov.setValidatorKey(await signers[3].getAddress(), badKey as `0x${string}`)
      ).to.be.revertedWith("Bridge: invalid key size");
    });
  });

  // ---------------------------------------------------------------------------
  // Governance
  // ---------------------------------------------------------------------------

  describe("setGovernance", function () {
    it("should let governance transfer ownership", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const newGov = signers[4];

      const bridgeAsGov = bridge.connect(govSigner as any);
      await bridgeAsGov.setGovernance(await newGov.getAddress());

      expect(await bridge.governance()).to.equal(await newGov.getAddress());
    });

    it("should revert when non-governance calls setGovernance", async function () {
      const signers = await ethers.getSigners();
      const nonGov = signers[2];

      const bridgeAsNonGov = bridge.connect(nonGov as any);
      await expect(
        bridgeAsNonGov.setGovernance(await signers[3].getAddress())
      ).to.be.revertedWith("Bridge: only governance");
    });

    it("should emit GovernanceChanged event", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];
      const newGov = signers[4];

      const bridgeAsGov = bridge.connect(govSigner as any);
      await expect(bridgeAsGov.setGovernance(await newGov.getAddress()))
        .to.emit(bridge, "GovernanceChanged")
        .withArgs(await govSigner.getAddress(), await newGov.getAddress());
    });
  });

  describe("setPaused", function () {
    it("should let governance pause the bridge", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];

      const bridgeAsGov = bridge.connect(govSigner as any);
      await bridgeAsGov.setPaused(true);

      expect(await bridge.paused()).to.equal(true);
    });

    it("should emit BridgePaused event", async function () {
      const signers = await ethers.getSigners();
      const govSigner = signers[0];

      const bridgeAsGov = bridge.connect(govSigner as any);
      await expect(bridgeAsGov.setPaused(true))
        .to.emit(bridge, "BridgePaused")
        .withArgs(true);
    });
  });

  // ---------------------------------------------------------------------------
  // View functions
  // ---------------------------------------------------------------------------

  describe("isTokenRegistered", function () {
    it("should return true for registered token", async function () {
      expect(await bridge.isTokenRegistered(wrappedToken.target)).to.equal(true);
    });

    it("should return false for unregistered token", async function () {
      const unregistered = "0x1234567890123456789012345678901234567890";
      expect(await bridge.isTokenRegistered(unregistered)).to.equal(false);
    });
  });

  describe("getNonce", function () {
    it("should return current nonce for user", async function () {
      const signers = await ethers.getSigners();
      const nonce = await bridge.getNonce(await signers[2].getAddress());
      expect(typeof nonce).to.equal("bigint");
    });
  });
});
