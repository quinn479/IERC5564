require("dotenv").config();

require("@nomiclabs/hardhat-web3");

const {
  TASK_TEST,
  TASK_COMPILE_GET_COMPILER_INPUT,
} = require("hardhat/builtin-tasks/task-names");

require("@nomiclabs/hardhat-waffle");
// require("@nomiclabs/hardhat-etherscan");
require("@nomiclabs/hardhat-ethers");
require("@openzeppelin/hardhat-upgrades");
require("hardhat-gas-reporter");
require("hardhat-abi-exporter");
require("solidity-coverage");
require("hardhat-deploy-ethers");
require("hardhat-deploy");

// This must occur after hardhat-deploy!
task(TASK_COMPILE_GET_COMPILER_INPUT).setAction(async (_, __, runSuper) => {
  const input = await runSuper();
  input.settings.metadata.useLiteralContent =
    process.env.USE_LITERAL_CONTENT != "false";
  console.log(
    `useLiteralContent: ${input.settings.metadata.useLiteralContent}`
  );
  return input;
});

// Task to run deployment fixtures before tests without the need of "--deploy-fixture"
//  - Required to get fixtures deployed before running Coverage Reports
task(TASK_TEST, "Runs the coverage report", async (args, hre, runSuper) => {
  await hre.run("compile");
  await hre.deployments.fixture();
  return runSuper({ ...args, noCompile: true });
});

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
module.exports = {
  defaultNetwork: "hardhat",
  networks: {
    hardhat: {},
    bsc: {
      url: `https://bsc-dataseed.binance.org/`,
      gasPrice: 6e9,
      blockGasLimit: 22400000,
      accounts: [process.env.PRIVATE_KEY_MAINNET],
    },
    bsctestnet: {
      url: `https://data-seed-prebsc-2-s1.binance.org:8545`,
      gasPrice: 20e9,
      blockGasLimit: 22400000,
      accounts: [process.env.PRIVATE_KEY],
    }
  },
  solidity: {
    version: "0.8.0",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./build/artifacts",
    deploy: "./deploy",
    deployments: "./deployments",
  },
  mocha: {
    timeout: 20000,
  },
  gasReporter: {
    currency: "USD",
    gasPrice: 1,
    enabled: process.env.REPORT_GAS ? true : false,
  },
  abiExporter: {
    path: "./abi",
    clear: true,
    flat: true,
  },
  // etherscan: {
  //   // Your API key for Etherscan
  //   // Obtain one at https://bscscan.com/
  //   // apiKey: process.env.BSC_APIKEY,
  // },
  namedAccounts: {
    deployer: {
      default: 0,
    },
    protocolOwner: {
      default: 1,
    },
    initialMinter: {
      default: 2,
    },
    user1: {
      default: 3,
    },
    user2: {
      default: 4,
    },
    user3: {
      default: 5,
    },
    trustedForwarder: {
    },
  },
};
