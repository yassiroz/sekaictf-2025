import { Address, beginCell, Cell, Contract, contractAddress, ContractProvider, Sender, SendMode } from '@ton/core';

export type BaseContractConfig = {
    deployer: Address;
    id: bigint;
};

export function BaseContractConfigToCell(config: BaseContractConfig): Cell {
    return beginCell()
        .storeAddress(config.deployer)
        .storeUint(config.id, 256)
    .endCell();
}

export class BaseContract implements Contract {
    constructor(readonly address: Address, readonly init?: { code: Cell; data: Cell }) {}

    static createFromAddress(address: Address) {
        return new BaseContract(address);
    }

    static createFromConfig(config: BaseContractConfig, code: Cell, workchain = 0) {
        const data = BaseContractConfigToCell(config);
        const init = { code, data };
        return new BaseContract(contractAddress(workchain, init), init);
    }

    async sendDeploy(provider: ContractProvider, via: Sender, value: bigint, body: Cell = beginCell().endCell()) {
        await provider.internal(via, {
            value,
            sendMode: SendMode.PAY_GAS_SEPARATELY,
            body,
        });
    }

    async sendMessage(provider: ContractProvider, sender: Sender, value: bigint, body: Cell) {
        await provider.internal(sender, {
            value,
            sendMode: SendMode.PAY_GAS_SEPARATELY,
            body,
        });
    }
}