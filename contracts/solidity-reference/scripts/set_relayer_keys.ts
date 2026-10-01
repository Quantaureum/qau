import { ethers } from "hardhat";

/**
 * Script to set relayer Dilithium3 public keys on bridge contracts.
 *
 * Run after deploying bridges:
 *   npx hardhat run scripts/set_relayer_keys.ts --network quantaureum
 *   npx hardhat run scripts/set_relayer_keys.ts --network quantaureum_mainnet
 */
async function main() {
  const networkName = ethers.provider.network.name;
  console.log(`Setting relayer keys on ${networkName}...`);

  const [deployer] = await ethers.getSigners();
  const governance = process.env.GOVERNANCE_ADDRESS || deployer.address;
  const relayerKeyBase64 = process.env.RELAYER_PUBLIC_KEY_BASE64;

  if (!relayerKeyBase64) {
    console.log("SKIP: RELAYER_PUBLIC_KEY_BASE64 not set");
    return;
  }

  const relayerKeyBytes = Buffer.from(relayerKeyBase64, "base64");
  console.log(`Relayer key length: ${relayerKeyBytes.length} bytes (expected 1952 for Dilithium3)`);

  // Set on the external-chain bridge contract
  const ethBridgeAddress = process.env.ETHEREUM_BRIDGE_ADDRESS;
  if (ethBridgeAddress) {
    const ethBridge = await ethers.getContractAt("EthereumBridge", ethBridgeAddress);
    const tx = await ethBridge.setRelayerKey(relayerKeyBytes);
    await tx.wait();
    console.log(`EthereumBridge: set relayer key (tx: ${tx.hash})`);
  }

  // Set on QuantaureumBridge
  const qauBridgeAddress = process.env.QUANTAUREUM_BRIDGE_ADDRESS;
  if (qauBridgeAddress) {
    const qauBridge = await ethers.getContractAt("QuantaureumBridge", qauBridgeAddress);
    // For QuantaureumBridge, validator keys are set individually per validator
    console.log(`QuantaureumBridge: use setValidatorKey() per validator`);
  }

  // Authorize relayer address
  const relayerAddress = process.env.RELAYER_ADDRESS;
  if (relayerAddress && ethBridgeAddress) {
    const ethBridge = await ethers.getContractAt("EthereumBridge", ethBridgeAddress);
    const tx = await ethBridge.setRelayerAuthorization(relayerAddress, true);
    await tx.wait();
    console.log(`EthereumBridge: authorized relayer ${relayerAddress}`);
  }

  if (relayerAddress && qauBridgeAddress) {
    const qauBridge = await ethers.getContractAt("QuantaureumBridge", qauBridgeAddress);
    const tx = await qauBridge.setRelayerAuthorization(relayerAddress, true);
    await tx.wait();
    console.log(`QuantaureumBridge: authorized relayer ${relayerAddress}`);
  }

  console.log("Done.");
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
