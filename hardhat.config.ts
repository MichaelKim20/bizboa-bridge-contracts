import "@nomicfoundation/hardhat-ledger";
import "@nomiclabs/hardhat-ethers";
import "@nomiclabs/hardhat-etherscan";
import "@nomiclabs/hardhat-waffle";
import "@typechain/hardhat";
import "hardhat-gas-reporter";

import * as dotenv from "dotenv";
import { Wallet } from "ethers";

dotenv.config({});

const env_network = process.env.ENV_NETWORK || "";
if (env_network !== "") {
    const envFileName = `env/.${env_network}.env`;
    console.log(`ENV FileName ${envFileName}`);
    dotenv.config({ path: envFileName });
} else {
    const envFileName = `env/.env`;
    console.log(`ENV FileName ${envFileName}`);
    dotenv.config({ path: envFileName });
}

import { HardhatAccount } from "./src/HardhatAccount";

// If not defined, randomly generated.
function getAccounts() {
    if (HardhatAccount.keys.length !== 0) return HardhatAccount.keys;

    const accounts: string[] = [];
    const reg_bytes64: RegExp = /^(0x)[0-9a-f]{64}$/i;
    const reg_bytes40: RegExp = /^(0x)[0-9a-f]{40}$/i;
    if (
        process.env.ADMIN_KEY === undefined ||
        process.env.ADMIN_KEY.trim() === "" ||
        !reg_bytes64.test(process.env.ADMIN_KEY)
    ) {
        console.log("환경 변수에 `ADMIN_KEY` 이 존재하지 않아서 무작위로 생성합니다.");
        process.env.ADMIN_KEY = Wallet.createRandom().privateKey;
        accounts.push(process.env.ADMIN_KEY);
    }
    if (
        process.env.MANAGER_KEY === undefined ||
        process.env.MANAGER_KEY.trim() === "" ||
        !reg_bytes64.test(process.env.MANAGER_KEY)
    ) {
        console.log("환경 변수에 `MANAGER_KEY` 이 존재하지 않아서 무작위로 생성합니다.");
        process.env.MANAGER_KEY = Wallet.createRandom().privateKey;
        accounts.push(process.env.MANAGER_KEY);
    }
    if (
        process.env.USER_KEY === undefined ||
        process.env.USER_KEY.trim() === "" ||
        !reg_bytes64.test(process.env.USER_KEY)
    ) {
        console.log("환경 변수에 `USER_KEY` 이 존재하지 않아서 무작위로 생성합니다.");
        process.env.USER_KEY = Wallet.createRandom().privateKey;
        accounts.push(process.env.USER_KEY);
    }

    if (
        process.env.FEE_MANAGER_ADDRESS === undefined ||
        process.env.FEE_MANAGER_ADDRESS.trim() === "" ||
        !reg_bytes40.test(process.env.FEE_MANAGER_ADDRESS)
    ) {
        console.log("환경 변수에 `FEE_MANAGER_ADDRESS` 이 존재하지 않아서 무작위로 생성합니다.");
        process.env.FEE_MANAGER_ADDRESS = Wallet.createRandom().address;
    }

    while (accounts.length < 10) {
        accounts.push(Wallet.createRandom().privateKey);
    }

    for (const account of accounts) {
        HardhatAccount.keys.push(account);
    }

    return HardhatAccount.keys;
}

function getTestAccounts() {
    const defaultBalance = "2000000000000000000000000";
    const acc = getAccounts();
    return acc.map((m) => {
        return {
            privateKey: m,
            balance: defaultBalance,
        };
    });
}

function getLedgerAccounts() {
    if (HardhatAccount.ledgerAddress.length !== 0) return HardhatAccount.ledgerAddress;

    const addresses: string[] = [];
    const reg_bytes64: RegExp = /^(0x)[0-9a-f]{40}$/i;

    if (
        process.env.ADMIN_ADDRESS !== undefined &&
        process.env.ADMIN_ADDRESS.trim() !== "" &&
        reg_bytes64.test(process.env.ADMIN_ADDRESS)
    ) {
        addresses.push(process.env.ADMIN_ADDRESS);
    }

    if (
        process.env.MANAGER_ADDRESS !== undefined &&
        process.env.MANAGER_ADDRESS.trim() !== "" &&
        reg_bytes64.test(process.env.MANAGER_ADDRESS)
    ) {
        addresses.push(process.env.MANAGER_ADDRESS);
    }

    if (
        process.env.USER_ADDRESS !== undefined &&
        process.env.USER_ADDRESS.trim() !== "" &&
        reg_bytes64.test(process.env.USER_ADDRESS)
    ) {
        addresses.push(process.env.USER_ADDRESS);
    }

    if (
        process.env.FEE_MANAGER_ADDRESS !== undefined &&
        process.env.FEE_MANAGER_ADDRESS.trim() !== "" &&
        reg_bytes64.test(process.env.FEE_MANAGER_ADDRESS)
    ) {
        addresses.push(process.env.FEE_MANAGER_ADDRESS);
    }

    for (const account of addresses) {
        HardhatAccount.ledgerAddress.push(account);
    }
    return HardhatAccount.ledgerAddress;
}

// You need to export an object to set up your config
// Go to https://hardhat.org/config/ to learn more

const config = {
    solidity: {
        compilers: [
            {
                version: "0.8.0",
            },
        ],
    },
    networks: {
        hardhat: {
            accounts: getTestAccounts(),
        },
        bosagora: {
            url: process.env.BOSAGORA_MAIN_NET_URL || "",
            chainId: 2151,
            ledgerAccounts: getLedgerAccounts(),
        },
        testnet: {
            url: process.env.BOSAGORA_TEST_NET_URL || "",
            chainId: 2019,
            ledgerAccounts: getLedgerAccounts(),
        },
        ethereum: {
            url: process.env.ETHEREUM_URL || "",
            chainId: 1,
            ledgerAccounts: getLedgerAccounts(),
        },
        sepolia: {
            url: process.env.SEPOLIA_URL || "",
            chainId: 11155111,
            ledgerAccounts: getLedgerAccounts(),
        },
    },
    etherscan: {
        apiKey: {
            mainnet: process.env.ETHERSCAN_API_KEY || "",
            sepolia: process.env.ETHERSCAN_API_KEY || "",
        },
    },
    gasReporter: {
        enabled: process.env.REPORT_GAS !== undefined,
        currency: "USD",
    },
};

export default config;
