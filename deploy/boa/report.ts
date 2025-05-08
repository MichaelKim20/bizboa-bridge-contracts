import "@nomiclabs/hardhat-ethers";
import { ethers } from "hardhat";

import { HardhatAccount } from "../../src/HardhatAccount";
import { BOAToken } from "../../src/utils/Amount";
import { BOATokenBridge, BOATokenBridge__factory, ERC20, TestToken, TestToken__factory } from "../../typechain-types";

import { Signer } from "@ethersproject/abstract-signer";
import { AddressZero } from "@ethersproject/constants";
import { NonceManager } from "@ethersproject/experimental";
import { BaseContract } from "ethers";
import { BOACoin } from "../../utils/Amount";

interface IChainInfo {
    boaAddress: string;
    bridgeAddress: string;
    timeLock: number;
    managerAddress: string;
    feeManagerAddress: string;
}

export const CHAIN_INFORMATION: { [key: string]: IChainInfo } = {
    1: {
        boaAddress: "0x51bD4f39803fcAEFf3ef45aae2C3aaFf0B9faDcb",
        bridgeAddress: AddressZero,
        timeLock: 60 * 60 * 24,
        managerAddress: "0x57e28abec087e7f3dbe4090a1352b32538f5d390",
        feeManagerAddress: "0x064c9Fc53d5936792845ca58778a52317fCf47F2",
    },
    11155111: {
        boaAddress: AddressZero,
        bridgeAddress: AddressZero,
        timeLock: 60 * 60 * 24,
        managerAddress: "0xAe3CF2FA59c59a2baAf3bFDF29DCF8537Fa88692",
        feeManagerAddress: "0x7c46A24C574B865E0f48E4FC0D52D95cF8a5B4C1",
    },
    24680: {
        boaAddress: AddressZero,
        bridgeAddress: AddressZero,
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

    public async attach() {
        {
            const contractName = "BOAToken";
            const factory = (await ethers.getContractFactory("TestToken")) as TestToken__factory;
            const contract = factory.attach(CHAIN_INFORMATION[this.chainId].boaAddress);
            this.addContract(contractName, contract.address, contract);
            console.log(`Attached ${contractName} to ${contract.address}`);
        }

        {
            const contractName = "BOATokenBridge";
            const factory = (await ethers.getContractFactory("BOATokenBridge")) as BOATokenBridge__factory;
            const contract = factory.attach(CHAIN_INFORMATION[this.chainId].bridgeAddress);
            this.addContract(contractName, contract.address, contract);
            console.log(`Attached ${contractName} to ${contract.address}`);
        }
    }
}

async function assignManager(accounts: IAccount, deployment: Deployments) {
    console.log(`Start Assign Manager`);
    if (deployment.getContract("BOATokenBridge") === undefined) {
        console.error("BOATokenBridge is not deployed!");
        return;
    }

    const bridge = deployment.getContract("BOATokenBridge") as BOATokenBridge;
    const managerAddress = CHAIN_INFORMATION[deployment.chainId].managerAddress;
    if (!(await bridge.isManager(managerAddress))) {
        const tx = await bridge.addManager(managerAddress);
        console.log(`Assign Manager (tx: ${tx.hash})...`);
        await tx.wait();
    }
    console.log(`End Assign Manager to ${managerAddress}`);
}

async function unassignManager(accounts: IAccount, deployment: Deployments) {
    console.log(`Start Assign Manager`);
    if (deployment.getContract("BOATokenBridge") === undefined) {
        console.error("BOATokenBridge is not deployed!");
        return;
    }

    const bridge = deployment.getContract("BOATokenBridge") as BOATokenBridge;
    const managerAddress = CHAIN_INFORMATION[deployment.chainId].managerAddress;
    if (!(await bridge.isManager(managerAddress))) {
        const tx = await bridge.removeManager(managerAddress);
        console.log(`Assign Manager (tx: ${tx.hash})...`);
        await tx.wait();
    }
    console.log(`End Assign Manager to ${managerAddress}`);
}

async function report(accounts: IAccount, deployment: Deployments) {
    if (deployment.getContract("BOAToken") === undefined) {
        console.error("OldBOAToken is not deployed!");
        return;
    }
    if (deployment.getContract("BOATokenBridge") === undefined) {
        console.error("BOATokenBridge is not deployed!");
        return;
    }

    const token = deployment.getContract("BOAToken") as ERC20;
    const bridge = deployment.getContract("BOATokenBridge") as BOATokenBridge;
    const deployerAddress = await accounts.deployer.getAddress();

    console.log(`Report`);
    console.log(`1. Addresses`);
    console.log(`BOA: ${token.address}`);
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
    console.log(`Balance, deployer : ${new BOAToken(await token.balanceOf(deployerAddress)).toDisplayString(true, 2)}`);
    console.log(`Balance, Bridger : ${new BOAToken(await token.balanceOf(bridge.address)).toDisplayString(true, 2)}`);
    console.log(`Balance, Manager : ${new BOAToken(await token.balanceOf(managerAddress)).toDisplayString(true, 2)}`);

    console.log(`3. Balances (ETH)`);
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
    await deployments.attach();
    deployments.addDeployer(report);
    await deployments.doDeploy();
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
