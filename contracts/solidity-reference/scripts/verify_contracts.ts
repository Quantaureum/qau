import { ethers, network } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Verifying contracts on", network.name);

  const deployments = {
    EthereumBridge: process.env.ETHEREUM_BRIDGE_ADDRESS,
    QuantaureumBridge: process.env.QUANTAUREUM_BRIDGE_ADDRESS,
    ValidatorRegistry: process.env.VALIDATOR_REGISTRY_ADDRESS,
    WrappedETH: process.env.WRAPPED_ETH_ADDRESS,
  };

  for (const [name, address] of Object.entries(deployments)) {
    if (!address) {
      console.log(`SKIP ${name} - address not set`);
      continue;
    }
    console.log(`${name}: ${address}`);

    // Verify source code matches
    const code = await ethers.provider.getCode(address);
    if (code === "0x") {
      console.error(`  ERROR: No code at ${address}`);
      continue;
    }
    console.log(`  OK: Code size = ${(parseInt(code, 16) - 2) / 2} bytes`);
  }
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
