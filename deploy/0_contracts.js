const {
  chainNameById,
  chainIdByName,
  saveDeploymentData,
  getContractAbi,
  getTxGasCost,
  log
} = require("../js-helpers/deploy");

const _ = require('lodash');

module.exports = async (hre) => {
    const { ethers, getNamedAccounts } = hre;
    const { deployer } = await getNamedAccounts();
    const network = await hre.network;
    const deployData = {};

    const chainId = chainIdByName(network.name);

    log('\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~');
    log('IERC5564 Contract Deployment');
    log('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n');

    log('  Using Network: ', chainNameById(chainId));
    log('  Using Accounts:');
    log('  - Deployer:          ', deployer);
    log('  - network id:          ', chainId);
    log(' ');

    log('  Deploying Router...');
    const SamnpleRegistry = await ethers.getContractFactory('SampleRegistry');
    const SamnpleRegistryInstance = await SamnpleRegistry.deploy()
    const instance = await SamnpleRegistryInstance.deployed()
    log('  - SampleRegistry:         ', instance.address);
    deployData['SampleRegistry'] = {
      abi: getContractAbi('SampleRegistry'),
      address: instance.address,
      deployTransaction: instance.deployTransaction,
    }

    const SamnpleGenerator = await ethers.getContractFactory('SampleGenerator');
    const SamnpleGeneratorInstance = await SamnpleGenerator.deploy()
    const generatorInstance = await SamnpleGeneratorInstance.deployed()

    await generatorInstance.initialize(instance.address)

    log('  - SampleGenerator:         ', generatorInstance.address);
    deployData['SampleGenerator'] = {
      abi: getContractAbi('SampleGenerator'),
      address: generatorInstance.address,
      deployTransaction: generatorInstance.deployTransaction,
    }

    const SamnpleMessenger = await ethers.getContractFactory('SampleMessenger');
    const SamnpleMessengerInstance = await SamnpleMessenger.deploy()
    const messengerInstance = await SamnpleMessengerInstance.deployed()
    log('  - SampleMessenger:         ', messengerInstance.address);
    deployData['SampleMessenger'] = {
      abi: getContractAbi('SampleMessenger'),
      address: messengerInstance.address,
      deployTransaction: messengerInstance.deployTransaction,
    }

    saveDeploymentData(chainId, deployData);
    log('\n  Contract Deployment Data saved to "deployments" directory.');

    log('\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n');
};

module.exports.tags = ['contracts']
