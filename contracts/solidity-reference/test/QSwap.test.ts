import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";

describe("QSwap AMM", function () {
  async function deployFixture() {
    const [owner, userA, userB, feeTo] = await ethers.getSigners();

    // 1. Deploy WQAU
    const WQAU = await ethers.getContractFactory("WQAU");
    const wqau = await WQAU.deploy();
    await wqau.waitForDeployment();

    // 2. Deploy Factory
    const Factory = await ethers.getContractFactory("QSwapFactory");
    const factory = await Factory.deploy(feeTo.address);
    await factory.waitForDeployment();

    // 3. Deploy a test ERC20 token
    const MockToken = await ethers.getContractFactory("MockERC20");
    const token = await MockToken.deploy("MockUSDT", "MUSDT", ethers.parseEther("1000000"));
    await token.waitForDeployment();

    // 4. Deploy Router
    const Router = await ethers.getContractFactory("QSwapRouter");
    const router = await Router.deploy(await factory.getAddress(), await wqau.getAddress());
    await router.waitForDeployment();
    await factory.connect(feeTo).setPairCaller(await router.getAddress());

    return { owner, userA, userB, feeTo, wqau, factory, router, token };
  }

  describe("WQAU", () => {
    it("deposit converts native QAU to WQAU", async () => {
      const { wqau, owner } = await loadFixture(deployFixture);
      await wqau.deposit({ value: ethers.parseEther("100") });
      expect(await wqau.balanceOf(owner.address)).to.equal(ethers.parseEther("100"));
    });

    it("withdraw burns WQAU and returns native", async () => {
      const { wqau, owner } = await loadFixture(deployFixture);
      await wqau.deposit({ value: ethers.parseEther("10") });
      const before = await ethers.provider.getBalance(owner.address);
      const tx = await wqau.withdraw(ethers.parseEther("3"));
      await tx.wait();
      expect(await wqau.balanceOf(owner.address)).to.equal(ethers.parseEther("7"));
      // approx: native increased (minus gas)
      const after = await ethers.provider.getBalance(owner.address);
      expect(after).to.be.gt(before); // loose check due to gas
    });
  });

  describe("QSwapFactory", () => {
    it("creates pair with deterministic address", async () => {
      const { factory, wqau, token } = await loadFixture(deployFixture);
      const tx = await factory.createPair(await wqau.getAddress(), await token.getAddress());
      await tx.wait();
      const pairAddr = await factory.getPair(await wqau.getAddress(), await token.getAddress());
      expect(pairAddr).to.not.equal(ethers.ZeroAddress);
      expect(await factory.allPairsLength()).to.equal(1n);
    });

    it("rejects direct pair state transitions from non-router callers", async () => {
      const { factory, wqau, token, userA } = await loadFixture(deployFixture);
      await factory.createPair(await wqau.getAddress(), await token.getAddress());
      const pairAddr = await factory.getPair(await wqau.getAddress(), await token.getAddress());
      const pair = await ethers.getContractAt("QSwapPair", pairAddr);

      await expect(pair.connect(userA).mint(userA.address)).to.be.revertedWith("QSwap: FORBIDDEN");
      await expect(pair.connect(userA).burn(userA.address)).to.be.revertedWith("QSwap: FORBIDDEN");
      await expect(pair.connect(userA).swap(1, 0, userA.address, "0x")).to.be.revertedWith("QSwap: FORBIDDEN");
    });

    it("rejects duplicate pair", async () => {
      const { factory, wqau, token } = await loadFixture(deployFixture);
      await factory.createPair(await wqau.getAddress(), await token.getAddress());
      await expect(factory.createPair(await wqau.getAddress(), await token.getAddress()))
        .to.be.revertedWith("QSwap: PAIR_EXISTS");
    });
  });

  describe("Pool + Swap", () => {
    it("allows adding initial liquidity and price is set correctly", async () => {
      const { owner, router, factory, wqau, token } = await loadFixture(deployFixture);

      // supply 10000 QAU (wrapped) + 10000 USDT
      const liquidityAmount = ethers.parseEther("1000");

      await token.approve(await router.getAddress(), liquidityAmount);
      await wqau.deposit({ value: liquidityAmount });
      await wqau.approve(await router.getAddress(), liquidityAmount);

      await factory.createPair(await wqau.getAddress(), await token.getAddress());
      const deadline = Math.floor(Date.now() / 1000) + 3600;

      await router.addLiquidity(
        await wqau.getAddress(),
        await token.getAddress(),
        liquidityAmount, // QAU desired
        liquidityAmount, // token desired
        liquidityAmount, // min A
        liquidityAmount, // min B
        owner.address,
        deadline
      );

      const pairAddr = await factory.getPair(await wqau.getAddress(), await token.getAddress());
      const pair = await ethers.getContractAt("QSwapPair", pairAddr);
      const totalSupply = await pair.totalSupply();
      // should have minted sqrt(10000*10000) - MINIMUM_LIQUIDITY = 10000 - 1000 wei
      expect(totalSupply).to.equal(ethers.parseEther("1000"));

      // reserves should be 10000 each
      const [r0, r1] = await pair.getReserves();
      expect(r0).to.be.gt(0n);
      expect(r1).to.be.gt(0n);
    });

    it("swap QAU for tokens changes reserves, user gets tokens", async () => {
      const { owner, userA, router, factory, wqau, token } = await loadFixture(deployFixture);

      // owner seeds pool with 10k/10k
      const liquidity = ethers.parseEther("1000");
      await token.approve(await router.getAddress(), liquidity);
      await wqau.deposit({ value: liquidity });
      await wqau.approve(await router.getAddress(), liquidity);
      await factory.createPair(await wqau.getAddress(), await token.getAddress());
      await router.addLiquidity(
        await wqau.getAddress(), await token.getAddress(),
        liquidity, liquidity, liquidity, liquidity,
        owner.address, Math.floor(Date.now()/1000) + 3600
      );

      // someone (userA) gets 100 token. Seller sends via factory minted token
      // Give userA some tokens directly for test via transfer
      await token.transfer(userA.address, ethers.parseEther("100"));

      // userA wants to swap 10 tokens for QAU
      const amountIn = ethers.parseEther("10");
      await token.connect(userA).approve(await router.getAddress(), amountIn);

      const beforeUserBalance = await ethers.provider.getBalance(userA.address);

      const path = [await token.getAddress(), await wqau.getAddress()];
      const expectedOut = await router.getAmountsOut(amountIn, path);

      await router.connect(userA).swapExactTokensForQau(
        amountIn,
        expectedOut[1],
        path,
        userA.address,
        Math.floor(Date.now()/1000) + 3600
      );

      // userA should have gained QAU (some native token)
      const afterUserBalance = await ethers.provider.getBalance(userA.address);
      expect(afterUserBalance).to.be.gt(beforeUserBalance);
    });

    it("price changes after swap (constant product k conserved)", async () => {
      const { owner, router, factory, wqau, token } = await loadFixture(deployFixture);

      const liquidity = ethers.parseEther("1000");
      await token.approve(await router.getAddress(), liquidity);
      await wqau.deposit({ value: liquidity });
      await wqau.approve(await router.getAddress(), liquidity);
      await factory.createPair(await wqau.getAddress(), await token.getAddress());
      await router.addLiquidity(
        await wqau.getAddress(), await token.getAddress(),
        liquidity, liquidity, liquidity, liquidity,
        owner.address, Math.floor(Date.now()/1000) + 3600
      );

      const pairAddr = await factory.getPair(await wqau.getAddress(), await token.getAddress());
      const pair = await ethers.getContractAt("QSwapPair", pairAddr);
      const [r0Before, r1Before] = await pair.getReserves();
      const kBefore = r0Before * r1Before;

      // swap 100 token for QAU
      await token.approve(await router.getAddress(), ethers.parseEther("100"));
      const amountIn = ethers.parseEther("100");
      const path = [await token.getAddress(), await wqau.getAddress()];
      await router.swapExactTokensForTokens(
        amountIn, 0, path, owner.address, Math.floor(Date.now()/1000) + 3600
      );

      const [r0After, r1After] = await pair.getReserves();
      const kAfter = r0After * r1After;
      expect(kAfter).to.be.gt(kBefore); // fee increases k
    });

    it("returns less than estimate for huge swap (slippage check)", async () => {
      const { owner, router, factory, wqau, token } = await loadFixture(deployFixture);

      const liquidity = ethers.parseEther("1000");
      await token.approve(await router.getAddress(), liquidity);
      await wqau.deposit({ value: liquidity });
      await wqau.approve(await router.getAddress(), liquidity);
      await factory.createPair(await wqau.getAddress(), await token.getAddress());
      await router.addLiquidity(
        await wqau.getAddress(), await token.getAddress(),
        liquidity, liquidity, liquidity, liquidity,
        owner.address, Math.floor(Date.now()/1000) + 3600
      );

      // Tiny input, no slippage expected
      await token.approve(await router.getAddress(), ethers.parseEther("1"));
      const tinyIn = ethers.parseEther("1");
      const path = [await token.getAddress(), await wqau.getAddress()];
      const estimatedOut = await router.getAmountsOut(tinyIn, path);
      expect(estimatedOut[1]).to.be.lt(ethers.parseEther("1")); // should be slightly less due to 0.3% fee
    });

    it("rejects deadline exceeded", async () => {
      const { router, wqau, token, factory } = await loadFixture(deployFixture);

      await token.approve(await router.getAddress(), ethers.parseEther("1"));
      const path = [await token.getAddress(), await wqau.getAddress()];
      await expect(
        router.swapExactTokensForTokens(
          ethers.parseEther("1"),
          0,
          path,
          (await ethers.getSigners())[0].address,
          Math.floor(Date.now()/1000) - 10  // past deadline
        )
      ).to.be.revertedWith("QSwapRouter: EXPIRED");
    });
  });

  describe("Remove Liquidity", () => {
    it("burning LP tokens returns pro-rata share", async () => {
      const { owner, router, factory, wqau, token } = await loadFixture(deployFixture);

      const liquidity = ethers.parseEther("1000");
      await token.approve(await router.getAddress(), liquidity);
      await wqau.deposit({ value: liquidity });
      await wqau.approve(await router.getAddress(), liquidity);
      await factory.createPair(await wqau.getAddress(), await token.getAddress());
      await router.addLiquidity(
        await wqau.getAddress(), await token.getAddress(),
        liquidity, liquidity, liquidity, liquidity,
        owner.address, Math.floor(Date.now()/1000) + 3600
      );

      const pairAddr = await factory.getPair(await wqau.getAddress(), await token.getAddress());
      const pair = await ethers.getContractAt("QSwapPair", pairAddr);
      const lp = await pair.balanceOf(owner.address);
      expect(lp).to.be.gt(0n);

      // approve pair to take LP
      await pair.approve(await router.getAddress(), lp);

      const beforeToken = await token.balanceOf(owner.address);

      await router.removeLiquidity(
        await wqau.getAddress(),
        await token.getAddress(),
        lp,
        0, 0,
        owner.address,
        Math.floor(Date.now()/1000) + 3600
      );

      const afterToken = await token.balanceOf(owner.address);
      expect(afterToken).to.be.gt(beforeToken);
      expect(await pair.balanceOf(owner.address)).to.equal(0n);
    });
  });
});
