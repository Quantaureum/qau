import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-ethers";
import "@nomicfoundation/hardhat-verify";
import "@nomicfoundation/hardhat-chai-matchers";
import "solidity-coverage";
import "hardhat-gas-reporter";
import * as dotenv from "dotenv";

dotenv.config();

const QUANTAUREUM_RPC = process.env.QUANTAUREUM_RPC || "http://localhost:8545";
const QUANTAUREUM_CHAIN_ID = 1669;

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      viaIR: false,
    },
  },

  networks: {
    hardhat: {
      chainId: 1669,
      mining: {
        auto: true,
        interval: 5000,
      },
      accounts: {
        mnemonic: "test test test test test test test test test test test junk",
        count: 20,
        path: "m/44'/60'/0'/0",
      },
    },
    localhost: {
      url: "http://127.0.0.1:8545",
      chainId: 1669,
    },
    quantaureum: {
      url: QUANTAUREUM_RPC,
      chainId: QUANTAUREUM_CHAIN_ID,
      accounts:
        process.env.DEPLOYER_PRIVATE_KEY !== undefined
          ? [process.env.DEPLOYER_PRIVATE_KEY]
          : [],
      gasPrice: "auto",
    },
    quantaureum_mainnet: {
      url: process.env.QUANTAUREUM_MAINNET_RPC || "https://rpc.quantaureum.com",
      chainId: 1668,
      accounts:
        process.env.DEPLOYER_PRIVATE_KEY !== undefined
          ? [process.env.DEPLOYER_PRIVATE_KEY]
          : [],
      gasPrice: "auto",
    },
  },

  etherscan: {
    customChains: [
      {
        network: "quantaureum",
        chainId: 1669,
        urls: {
          apiURL: process.env.QUANTAUREUM_EXPLORER_API || "https://testnet.quantaureum.com/api",
          browserURL: process.env.QUANTAUREUM_EXPLORER_URL || "https://testnet.quantaureum.com",
        },
      },
      {
        network: "quantaureum_mainnet",
        chainId: 1668,
        urls: {
          apiURL: process.env.QUANTAUREUM_MAINNET_EXPLORER_API || "https://explorer.quantaureum.com/api",
          browserURL: process.env.QUANTAUREUM_MAINNET_EXPLORER_URL || "https://explorer.quantaureum.com",
        },
      },
    ],
  },

  gasReporter: {
    enabled: process.env.REPORT_GAS === "true",
  },

  coverage: {
    enabled: process.env.ENABLE_COVERAGE === "true",
    thresholdTypes: {
      solc: ["function", "branch", "line"],
    },
  },

  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },

  typechain: {
    outDir: "./typechain",
    target: "ethers-v6",
  },
};

export default config;
