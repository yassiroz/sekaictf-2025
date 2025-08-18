import { Blockchain, printTransactionFees, SandboxContract, TreasuryContract } from '@ton/sandbox';
import { Cell, toNano, beginCell } from '@ton/core';
import '@ton/test-utils';
import { compile } from '@ton/blueprint';

import { OP } from '../wrappers/constants/opcode';
import { BaseContract } from '../wrappers/BaseContract';
import { ServiceCounter } from '../wrappers/ServiceCounter';
import { Minter } from '../wrappers/Minter';
import { Exploit } from '../wrappers/Exploit';

describe('Challenge', () => {
    const ARCADE_MACHINE_GAME_TYPE = 0;
    const ARCADE_MACHINE_ID = 0;

    let walletCode: Cell;
    let coinMinterCode: Cell;
    let ticketMinterCode: Cell;
    let serviceCounterCode: Cell;
    let baseCode: Cell;
    let exploitCode: Cell;

    beforeAll(async () => {
        walletCode = await compile('Wallet');
        coinMinterCode = await compile('CoinMinter');
        ticketMinterCode = await compile('TicketMinter');
        serviceCounterCode = await compile('ServiceCounter');
        baseCode = await compile('BaseContract');
        exploitCode = await compile('Exploit');
    });

    let blockchain: Blockchain;
    let deployer: SandboxContract<TreasuryContract>;
    let coinMinter: SandboxContract<Minter>;
    let ticketMinter: SandboxContract<Minter>;
    let serviceCounter: SandboxContract<ServiceCounter>;
    let arcadeMachine: SandboxContract<BaseContract>;
    let exploitDeployer: SandboxContract<TreasuryContract>;
    let exploit: SandboxContract<Exploit>;

    beforeEach(async () => {
        blockchain = await Blockchain.create();

        deployer = await blockchain.treasury('deployer');
        exploitDeployer = await blockchain.treasury('exploitDeployer');

        coinMinter = blockchain.openContract(Minter.createFromConfig({
            admin: deployer.address,
            walletCode: walletCode,
        }, coinMinterCode));

        ticketMinter = blockchain.openContract(Minter.createFromConfig({
            admin: deployer.address,
            walletCode: walletCode,
        }, ticketMinterCode));

        serviceCounter = blockchain.openContract(ServiceCounter.createFromConfig({
            admin: deployer.address,
            baseCode: baseCode,
            walletCode: walletCode,
            coinMinter: coinMinter.address,
            ticketMinter: ticketMinter.address,
        }, serviceCounterCode));

        arcadeMachine = blockchain.openContract(BaseContract.createFromConfig({
            deployer: serviceCounter.address,
            id: BigInt(`0x${beginCell()
                .storeUint(2, 4)    // contract type
                .storeUint(ARCADE_MACHINE_GAME_TYPE, 8)    // game type
                .storeUint(ARCADE_MACHINE_ID, 16)   // machine id
                .endCell().hash().toString('hex')}`),
        }, baseCode));
        const installArcadeMachinePayload = beginCell()
            .storeUint(OP.INSTALL_ARCADE_MACHINE, 32)
            .storeUint(0, 64)
            .storeUint(ARCADE_MACHINE_GAME_TYPE, 8)
            .storeUint(ARCADE_MACHINE_ID, 16)
            .endCell();
        let executeResult = await serviceCounter.sendDeploy(deployer.getSender(), toNano('0.5'), installArcadeMachinePayload);
        expect(executeResult.transactions).toHaveTransaction({
            from: serviceCounter.address,
            to: arcadeMachine.address,
            op: OP.INSTALL,
            success: true,
        });

        const changeAdminPayload = beginCell()
            .storeUint(OP.CHANGE_ADMIN, 32)
            .storeUint(0, 64)
            .storeAddress(serviceCounter.address)
            .endCell();
        executeResult = await coinMinter.sendDeploy(deployer.getSender(), toNano('0.5'), changeAdminPayload);
        expect(executeResult.transactions).toHaveTransaction({
            from: deployer.address,
            to: coinMinter.address,
            op: OP.CHANGE_ADMIN,
            success: true,
        });
        const coinMinterData = await coinMinter.getJettonData();
        expect(coinMinterData.adminAddress.toString()).toEqual(serviceCounter.address.toString());

        executeResult = await ticketMinter.sendDeploy(deployer.getSender(), toNano('0.5'), changeAdminPayload);
        expect(executeResult.transactions).toHaveTransaction({
            from: deployer.address,
            to: ticketMinter.address,
            op: OP.CHANGE_ADMIN,
            success: true,
        });

        executeResult = await serviceCounter.sendMessage(deployer.getSender(), toNano('0.5'), beginCell()
            .storeUint(OP.ADD_TICKET, 32)
            .storeUint(0, 64)
            .storeUint(ARCADE_MACHINE_GAME_TYPE, 8)
            .storeUint(ARCADE_MACHINE_ID, 16)
            .storeCoins(1500)
            .storeCoins(toNano('0.2'))
        .endCell());
        const arcadeMachineTicketWalletAddress = await ticketMinter.getWalletAddress(arcadeMachine.address);
        expect(executeResult.transactions).toHaveTransaction({
            from: arcadeMachineTicketWalletAddress,
            to: arcadeMachine.address,
            op: OP.TRANSFER_NOTIFICATION,
            success: true
        });
        
        exploit = blockchain.openContract(Exploit.createFromConfig({}, exploitCode));

        executeResult = await exploit.sendDeploy(exploitDeployer.getSender(), toNano('0.5'));
        expect(executeResult.transactions).toHaveTransaction({
            from: exploitDeployer.address,
            to: exploit.address,
            deploy: true,
            success: true,
        });
    });

    it('should deploy', async () => {
        // the check is done inside beforeEach
        // blockchain and challenge are ready to use
    });

    it('should solve', async () => {
        for (let i = 0; i < 5; i++) {
            let result = await exploitDeployer.send({
                to: exploit.address,
                value: toNano('1'),
                body: beginCell()
                    .storeUint(OP.EXPLOIT_RUN, 32) // exploit::op::run
                    .storeUint(i, 64)
                    .storeAddress(serviceCounter.address)
                    .storeAddress(coinMinter.address)
                    .storeAddress(ticketMinter.address)
                .endCell(),
            });
            printTransactionFees(result.transactions);
        }
        const solver = await serviceCounter.getSolver();
        const exploitAccount = blockchain.openContract(BaseContract.createFromConfig({
            deployer: serviceCounter.address,
            id: BigInt(`0x${beginCell()
                .storeUint(1, 4)    // contract type
                .storeAddress(exploit.address)
                .endCell().hash().toString('hex')}`),
        }, baseCode));
        if (solver === null) {
            throw new Error('The challenge is not solved!');
        }
        expect(solver.toString()).toEqual(exploitAccount.address.toString());
    });

});
