import "@nomiclabs/hardhat-ethers";
import { ethers } from "hardhat";

import { HardhatAccount } from "../../src/HardhatAccount";
import { BOAToken } from "../../src/utils/Amount";
import { BOACoinBridge, BOACoinBridge__factory, ERC20, TestToken, TestToken__factory } from "../../typechain-types";

import { Signer } from "@ethersproject/abstract-signer";
import { AddressZero } from "@ethersproject/constants";
import { NonceManager } from "@ethersproject/experimental";
import { BaseContract } from "ethers";
import { BOACoin } from "../../utils/Amount";

interface IChainInfo {
    boaAddress: string;
    bridgeAddress: string;
    bridgeOwner: string;
    timeLock: number;
    managerAddress: string;
    feeManagerAddress: string;
}

export const CHAIN_INFORMATION: { [key: string]: IChainInfo } = {
    1: {
        boaAddress: "0x51bD4f39803fcAEFf3ef45aae2C3aaFf0B9faDcb",
        bridgeAddress: AddressZero,
        bridgeOwner: "0xD871310905303fD11d50CE5006d7B8844155D3BD",
        timeLock: 60 * 60 * 24,
        managerAddress: "0xf66107cE2f17b94b7bB40e1e7274fa4962915551",
        feeManagerAddress: "0x064c9Fc53d5936792845ca58778a52317fCf47F2",
    },
    2151: {
        boaAddress: AddressZero,
        bridgeAddress: "0x95075eDc815e9Cd62Ff6D4598ea922307416B452",
        bridgeOwner: "0xD871310905303fD11d50CE5006d7B8844155D3BD",
        timeLock: 60 * 60 * 24,
        managerAddress: "0xf66107cE2f17b94b7bB40e1e7274fa4962915551",
        feeManagerAddress: "0x064c9Fc53d5936792845ca58778a52317fCf47F2",
    },
    11155111: {
        boaAddress: "0x0195a6DD3Aa109567bb38958D48a86b3A08BC48b",
        bridgeAddress: "0x1296aCf5d1F8Fbb9097fb2Ace1C4B5E3421050bE",
        bridgeOwner: "0x4adB23668AA8742F3c36C0103e0347140E59d60a",
        timeLock: 60 * 60 * 24,
        managerAddress: "0xAe3CF2FA59c59a2baAf3bFDF29DCF8537Fa88692",
        feeManagerAddress: "0x7c46A24C574B865E0f48E4FC0D52D95cF8a5B4C1",
    },
    2019: {
        boaAddress: AddressZero,
        bridgeAddress: "0xcC9Ca8D27a7E57b9e90A24F29C4f3dc80A6Dd020",
        bridgeOwner: "0x4adB23668AA8742F3c36C0103e0347140E59d60a",
        timeLock: 60 * 60 * 24,
        managerAddress: "0xAe3CF2FA59c59a2baAf3bFDF29DCF8537Fa88692",
        feeManagerAddress: "0x7c46A24C574B865E0f48E4FC0D52D95cF8a5B4C1",
    },
    24680: {
        boaAddress: AddressZero,
        bridgeAddress: AddressZero,
        bridgeOwner: "0x4adB23668AA8742F3c36C0103e0347140E59d60a",
        timeLock: 60 * 60 * 24,
        managerAddress: "0xAe3CF2FA59c59a2baAf3bFDF29DCF8537Fa88692",
        feeManagerAddress: "0x7c46A24C574B865E0f48E4FC0D52D95cF8a5B4C1",
    },
};

interface IDeployedContract {
    name: string;
    address: string;
    contract: BaseContract;
}

interface IAccount {
    deployer: Signer;
}

type FnDeployer = (accounts: IAccount, deployment: Deployments) => Promise<any>;

class Deployments {
    public deployments: Map<string, IDeployedContract>;
    public deployers: FnDeployer[];
    public accounts: IAccount | undefined;
    public chainId: number;

    constructor(chainId: number) {
        console.log("ChainId: ", chainId);

        this.chainId = chainId;
        this.deployments = new Map<string, IDeployedContract>();
        this.deployers = [];
        this.accounts = undefined;
    }

    public async initAccounts() {
        const deployer = new NonceManager(await ethers.getSigner(HardhatAccount.ledgerAddress[0]));

        this.accounts = {
            deployer,
        };

        console.log(`deployer: ${await deployer.getAddress()}`);
    }

    public addContract(name: string, address: string, contract: BaseContract) {
        this.deployments.set(name, {
            name,
            address,
            contract,
        });
    }

    public getContract(name: string): BaseContract | undefined {
        const info = this.deployments.get(name);
        if (info !== undefined) {
            return info.contract;
        } else {
            return undefined;
        }
    }

    public getContractAddress(name: string): string | undefined {
        const info = this.deployments.get(name);
        if (info !== undefined) {
            return info.address;
        } else {
            return undefined;
        }
    }

    public addDeployer(deployer: FnDeployer) {
        this.deployers.push(deployer);
    }

    public async doDeploy() {
        if (this.accounts === undefined) return;
        for (const elem of this.deployers) {
            try {
                await elem(this.accounts, this);
            } catch (error) {
                console.log(error);
            }
        }
    }
}

async function deployBridge(accounts: IAccount, deployment: Deployments) {
    const contractName = "BOACoinBridge";
    if (CHAIN_INFORMATION[deployment.chainId].bridgeAddress === AddressZero) {
        console.log(`Deploy ${contractName}...`);
        const timeLock = CHAIN_INFORMATION[deployment.chainId].timeLock;
        const feeManagerAddress = CHAIN_INFORMATION[deployment.chainId].feeManagerAddress;
        const factory = (await ethers.getContractFactory("BOACoinBridge")) as BOACoinBridge__factory;
        const contract = (await factory
            .connect(accounts.deployer)
            .deploy(timeLock, feeManagerAddress, false)) as BOACoinBridge;
        await contract.deployed();
        await contract.deployTransaction.wait();
        deployment.addContract(contractName, contract.address, contract);
        console.log(`Deployed ${contractName} to ${contract.address}`);
    } else {
        console.log(`Attach ${contractName}...`);
        const factory = (await ethers.getContractFactory("BOACoinBridge")) as BOACoinBridge__factory;
        const contract = factory.attach(CHAIN_INFORMATION[deployment.chainId].bridgeAddress);
        deployment.addContract(contractName, contract.address, contract);
        console.log(`Attached ${contractName} to ${contract.address}`);
    }
}

async function assignManager(accounts: IAccount, deployment: Deployments) {
    console.log(`Start Assign Manager`);
    if (deployment.getContract("BOACoinBridge") === undefined) {
        console.error("BOACoinBridge is not deployed!");
        return;
    }

    const bridge = deployment.getContract("BOACoinBridge") as BOACoinBridge;
    const managerAddress = CHAIN_INFORMATION[deployment.chainId].managerAddress;
    if (!(await bridge.isManager(managerAddress))) {
        const tx = await bridge.addManager(managerAddress);
        console.log(`Assign Manager (tx: ${tx.hash})...`);
        await tx.wait();
    }
    console.log(`End Assign Manager to ${managerAddress}`);
}

async function changeOwner(accounts: IAccount, deployment: Deployments) {
    console.log(`Start Assign Manager`);
    if (deployment.getContract("BOACoinBridge") === undefined) {
        console.error("BOACoinBridge is not deployed!");
        return;
    }

    const bridge = deployment.getContract("BOACoinBridge") as BOACoinBridge;
    const bridgeOwner = CHAIN_INFORMATION[deployment.chainId].bridgeOwner;

    const tx = await bridge.transferOwnership(bridgeOwner);
    console.log(`Transfer Ownership (tx: ${tx.hash})...`);
    await tx.wait();

    console.log(`Transfer Ownership to ${bridgeOwner}`);
}

async function report(accounts: IAccount, deployment: Deployments) {
    if (deployment.getContract("BOACoinBridge") === undefined) {
        console.error("BOACoinBridge is not deployed!");
        return;
    }

    const bridge = deployment.getContract("BOACoinBridge") as BOACoinBridge;
    const deployerAddress = await accounts.deployer.getAddress();

    console.log(`Report`);
    console.log(`1. Addresses`);
    console.log(`Bridger: ${bridge.address}`);
    console.log(`Deployer: ${deployerAddress}`);
    console.log(`Manager: ${CHAIN_INFORMATION[deployment.chainId].managerAddress}`);
    console.log(`FeeManager: ${CHAIN_INFORMATION[deployment.chainId].feeManagerAddress}`);

    const managerAddress = CHAIN_INFORMATION[deployment.chainId].managerAddress;
    console.log(`2. Contract values`);
    console.log(`Owner: ${await bridge.owner()}`);
    console.log(`Manager (${managerAddress}): ${await bridge.isManager(managerAddress)}`);
    console.log(`Manager (${deployerAddress}): ${await bridge.isManager(deployerAddress)}`);
    console.log(`FeeManager : ${await bridge.getFeeManager()}`);

    console.log(`3. Balances (BOA)`);
    console.log(
        `Balance, deployer : ${new BOACoin(await ethers.provider.getBalance(deployerAddress)).toDisplayString(true, 2)}`
    );
    console.log(
        `Balance, Bridger : ${new BOACoin(await ethers.provider.getBalance(bridge.address)).toDisplayString(true, 2)}`
    );
    console.log(
        `Balance, Manager : ${new BOACoin(await ethers.provider.getBalance(managerAddress)).toDisplayString(true, 2)}`
    );
}

async function main() {
    const network = await ethers.provider.getNetwork();
    const chainId = network.chainId;
    const deployments = new Deployments(chainId);

    await deployments.initAccounts();
    deployments.addDeployer(deployBridge);
    deployments.addDeployer(assignManager);
    // deployments.addDeployer(changeOwner);
    deployments.addDeployer(report);
    await deployments.doDeploy();
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
