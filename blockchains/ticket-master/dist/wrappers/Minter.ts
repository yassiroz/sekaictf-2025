import { Address, beginCell, Cell, Contract, contractAddress, ContractProvider, Sender, SendMode, TupleBuilder } from '@ton/core';

export type MinterConfig = {
    admin: Address;
    walletCode: Cell;
};

export function minterConfigToCell(config: MinterConfig): Cell {
    return beginCell()
    .storeCoins(0)
    .storeAddress(config.admin)
    .storeRef(config.walletCode)
    .endCell();
}

export class Minter implements Contract {
    constructor(readonly address: Address, readonly init?: { code: Cell; data: Cell }) {}

    static createFromAddress(address: Address) {
        return new Minter(address);
    }

    static createFromConfig(config: MinterConfig, code: Cell, workchain = 0) {
        const data = minterConfigToCell(config);
        const init = { code, data };
        return new Minter(contractAddress(workchain, init), init);
    }

    async sendDeploy(provider: ContractProvider, via: Sender, value: bigint, body: Cell = beginCell().endCell()) {
        await provider.internal(via, {
            value,
            sendMode: SendMode.PAY_GAS_SEPARATELY,
            body,
        });
    }

    async getJettonData(provider: ContractProvider) {
        const { stack } = await provider.get("get_jetton_data", []);
        const totalSupply = stack.readBigNumber();
        stack.readNumber();
        const adminAddress = stack.readAddress();
        return {
            totalSupply,
            adminAddress
        }
    }

    async getWalletAddress(provider: ContractProvider, owner: Address) {
        let builder = new TupleBuilder();
        builder.writeAddress(owner);
        const { stack } = await provider.get("get_wallet_address", builder.build());
        return stack.readAddress();
    }
}

