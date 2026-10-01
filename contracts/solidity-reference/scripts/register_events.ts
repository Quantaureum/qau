import { ethers } from "hardhat";

/**
 * Script to register bridge event signatures on QuantaureumBridge.
 * Event signatures must match the Go adapter's validEventSignatures allowlist.
 *
 * Run after deploying QuantaureumBridge:
 *   npx hardhat run scripts/register_events.ts --network quantaureum
 */
async function main() {
  const bridgeAddress = process.env.QUANTAUREUM_BRIDGE_ADDRESS;
  if (!bridgeAddress) throw new Error("QUANTAUREUM_BRIDGE_ADDRESS not set");

  const [deployer] = await ethers.getSigners();
  console.log("Registering events on QuantaureumBridge at", bridgeAddress);
  console.log("Deployer:", deployer.address);

  // These are the canonical event signatures for bridge operations.
  // They must match the Go adapter's validEventSignatures map keys.
  const eventSignatures = [
    {
      name: "TokensLocked",
      signature: ethers.id("TokensLocked(address,uint256,bytes32,bytes32)"),
    },
    {
      name: "ERC20Locked",
      signature: ethers.id("ERC20Locked(address,address,uint256,bytes32)"),
    },
    {
      name: "TokensBurned",
      signature: ethers.id("TokensBurned(address,uint256,address,bytes32)"),
    },
    {
      name: "WrappedTokenBurned",
      signature: ethers.id("WrappedTokenBurned(address,address,uint256,address)"),
    },
    {
      name: "UnlockProcessed",
      signature: ethers.id("UnlockProcessed(bytes32,address,uint256,uint64)"),
    },
  ];

  console.log("\nCanonical event signatures:");
  for (const event of eventSignatures) {
    console.log(`  ${event.name}: ${event.signature}`);
  }

  console.log("\nNote: QuantaureumBridge v1 does not have a registerEventSignature function.");
  console.log("Event signatures are verified by the Go relayer's adapter based on the");
  console.log("validEventSignatures allowlist in bridge/ethereum_adapter.go and");
  console.log("bridge/quantaureum_adapter.go.");
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
