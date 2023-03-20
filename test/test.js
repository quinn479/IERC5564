const { expect } = require('chai')
const { ethers, upgrades } = require('hardhat')
const { randomBytes, generateKeyPair } = require('crypto')
const secp256k1 = require('secp256k1')


const BigNumber = ethers.BigNumber
function toWei(n) {
    return ethers.utils.parseEther(n)
}

async function increaseTime(time) {
    let provider = ethers.provider
    await provider.send('evm_increaseTime', [time])
    await provider.send('evm_mine', [])
}

async function increaseBlock(blocks) {
    let provider = ethers.provider

    for (var i = 0; i < blocks; i++) {
        await provider.send('evm_mine', [])
    }
}

async function getRandomPairKey() {
    let ephemeralPri = await randomBytes(32)
    const ephemeralPriHex = Buffer.from(ephemeralPri).toString("hex") //"d5083da744f6dd22b06c47b081ee2492df67d0ec3586877476df7b0f700bf932" //Buffer.from(ephemeralPri).toString("hex")
    console.log("ephemeralPriHex : ", ephemeralPriHex)
    const ephemeralPub = secp256k1.publicKeyCreate(Uint8Array.from( Buffer.from(ephemeralPriHex, "hex")), false)
    let ephemeralPubHex = Buffer.from(ephemeralPub).toString("hex").slice(2)

    console.log(" ephemeralPubHex :", ephemeralPubHex)

    return {
        Pri: ephemeralPriHex,
        Pub: ephemeralPubHex,
    }



}


describe('IERC5564', async function () {
    const [
        owner,
        user1,
        user2,
        user3,
        user4,
        user5,
        minter,
    ] = await ethers.getSigners()

    let sampleregistry, samplegenerator, samplemesseger;
    let deadline = 999999999999
    beforeEach(async () => {

        const SampleRegistry = await ethers.getContractFactory('SampleRegistry')
        const SampleRegistryInstance = await SampleRegistry.deploy()
        sampleregistry = await SampleRegistryInstance.deployed()
        console.log("SampleRegistry address : ", sampleregistry.address)


        const SampleMessenger = await ethers.getContractFactory('SampleMessenger')
        const SampleMessegerInstance = await SampleMessenger.deploy()
        samplemesseger = await SampleMessegerInstance.deployed()
        console.log("SampleMesseger : ", samplemesseger.address)


        const SampleGenerator = await ethers.getContractFactory('SampleGenerator')
        const SampleGeneratorInstance = await SampleGenerator.deploy()
        samplegenerator = await SampleGeneratorInstance.deployed()
        await samplegenerator.initialize(sampleregistry.address)
        console.log("sampleGenerator : ", samplegenerator.address)
    })


    it("stealthKeyGen", async function () {
        console.log(" start test 1")
        console.log("================")
        
        console.log("user1 : ", user1.address)
        let viewPairUser1 = await getRandomPairKey();
        let spendPairUser1 = await getRandomPairKey();
        console.log("spend user 1: ", spendPairUser1)
        
        console.log("================")
        console.log("user2 : ", user2.address)
        let viewPairUser2 = await getRandomPairKey();
        let spendPairUser2 = await getRandomPairKey();
        console.log("view user2 : ", viewPairUser2)

        await sampleregistry.connect(user1).registerKeys(samplegenerator.address, "0x"+ spendPairUser1.Pub, "0x" +viewPairUser1.Pub )
        console.log("A")
        await sampleregistry.connect(user2).registerKeys(samplegenerator.address, "0x" + spendPairUser2.Pub, "0x" + viewPairUser2.Pub )

        console.log("====== Send ======")
        let ephemeral = await getRandomPairKey()
        let ephePri = "0x" + ephemeral.Pri
        console.log("pri: ", ephePri)
        let result = await samplegenerator.connect(user1).generateStealthAddress(user2.address,  ephePri)
        console.log(result)
        let stealthAddress = result.stealthAddress
        let ephemeralPubKey = result.ephemeralPubKey
        let sharedSecret = result.sharedSecret
        let viewTag = result.viewTag
        console.log(sharedSecret)


        let annouce = await samplemesseger.connect(user2).privateETHTransfer(stealthAddress, ephemeralPubKey, viewTag, viewTag )

        console.log(annouce)



    })

})