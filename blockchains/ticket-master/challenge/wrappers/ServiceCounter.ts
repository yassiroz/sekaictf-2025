import { Address, beginCell, Cell, Contract, contractAddress, ContractProvider, Sender, SendMode } from '@ton/core';

export type ServiceCounterConfig = {
    admin: Address;
    baseCode: Cell;
    walletCode: Cell;
    coinMinter: Address;
    ticketMinter: Address;
};

export function serviceCounterConfigToCell(config: ServiceCounterConfig): Cell {
    return beginCell()
        .storeAddress(config.admin)
        .storeRef(config.baseCode)
        .storeRef(config.walletCode)
        .storeRef(
            beginCell()
                .storeAddress(config.coinMinter)
                .storeAddress(config.ticketMinter)
            .endCell()
        )
        .storeUint(0, 2)
    .endCell();
}

export class ServiceCounter implements Contract {
    constructor(readonly address: Address, readonly init?: { code: Cell; data: Cell }) {}

    static createFromAddress(address: Address) {
        return new ServiceCounter(address);
    }

    static createFromConfig(config: ServiceCounterConfig, code: Cell, workchain = 0) {
        const data = serviceCounterConfigToCell(config);
        const init = { code, data };
        return new ServiceCounter(contractAddress(workchain, init), init);
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

    async getSolver(provider: ContractProvider) {
        const { stack } = await provider.get("get_solver", []);
        return stack.readAddressOpt();
    }
}