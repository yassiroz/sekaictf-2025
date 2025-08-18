import {Blockchain} from '@ton/sandbox';
import {beginCell, Cell, toNano} from '@ton/core';
import {ServiceCounter} from '../wrappers/ServiceCounter';
import {Minter} from '../wrappers/Minter';
import {BaseContract} from '../wrappers/BaseContract';
import {Exploit} from '../wrappers/Exploit';
import {OP} from '../wrappers/constants/opcode';
import '@ton/test-utils';
import {compile} from '@ton/blueprint';
import express, {Request, Response} from 'express';
import bodyParser from 'body-parser';

const FLAG = process.env.FLAG || 'ctf{test-flag}';

const app = express();
app.use(bodyParser.json());

let walletCode: Cell;
let coinMinterCode: Cell;
let ticketMinterCode: Cell;
let serviceCounterCode: Cell;
let baseCode: Cell;

compile('BaseContract').then(code => {
    baseCode = code;
});
compile('Wallet').then(code => {
    walletCode = code;
});
compile('CoinMinter').then(code => {
    coinMinterCode = code;
});
compile('TicketMinter').then(code => {
    ticketMinterCode = code;
});
compile('ServiceCounter').then(code => {
    serviceCounterCode = code;
});

app.post('/submit', async (req: Request, res: Response) => {
    try {
        const exploitCode = Cell.fromBase64(req.body.code);
        const steps = parseInt(req.body.steps);
        if (steps > 5) {
            res.status(400).json({ error: 'Cannot run more than 5 steps' });
            return;
        }
        
        const ARCADE_MACHINE_GAME_TYPE = 0;
        const ARCADE_MACHINE_ID = 0;
        const ARCADE_MACHINE_INITIAL_TICKET_AMOUNT = 1500;
        const blockchain = await Blockchain.create();

        const deployer = await blockchain.treasury('deployer');
        const exploitDeployer = await blockchain.treasury('exploitDeployer');
        
        // Deploy challenge contracts
        const coinMinter = blockchain.openContract(Minter.createFromConfig({
            admin: deployer.address,
            walletCode: walletCode,
        }, coinMinterCode));

        const ticketMinter = blockchain.openContract(Minter.createFromConfig({
            admin: deployer.address,
            walletCode: walletCode,
        }, ticketMinterCode));

        const serviceCounter = blockchain.openContract(ServiceCounter.createFromConfig({
            admin: deployer.address,
            baseCode: baseCode,
            walletCode: walletCode,
            coinMinter: coinMinter.address,
            ticketMinter: ticketMinter.address,
        }, serviceCounterCode));

        const installArcadeMachinePayload = beginCell()
            .storeUint(OP.INSTALL_ARCADE_MACHINE, 32)
            .storeUint(0, 64)
            .storeUint(ARCADE_MACHINE_GAME_TYPE, 8)
            .storeUint(ARCADE_MACHINE_ID, 16)
            .endCell();
        await serviceCounter.sendDeploy(deployer.getSender(), toNano('0.5'), installArcadeMachinePayload);

        const changeAdminPayload = beginCell()
            .storeUint(OP.CHANGE_ADMIN, 32)
            .storeUint(0, 64)
            .storeAddress(serviceCounter.address)
            .endCell();
        await coinMinter.sendDeploy(deployer.getSender(), toNano('0.5'), changeAdminPayload);
        await ticketMinter.sendDeploy(deployer.getSender(), toNano('0.5'), changeAdminPayload);

        // Initialize the arcade machine
        await serviceCounter.sendMessage(deployer.getSender(), toNano('0.5'), beginCell()
            .storeUint(OP.ADD_TICKET, 32)
            .storeUint(0, 64)
            .storeUint(ARCADE_MACHINE_GAME_TYPE, 8)
            .storeUint(ARCADE_MACHINE_ID, 16)
            .storeCoins(ARCADE_MACHINE_INITIAL_TICKET_AMOUNT)
            .storeCoins(toNano('0.2'))
        .endCell());
        
        // Deploy exploit contract
        const exploit = blockchain.openContract(Exploit.createFromConfig({}, exploitCode));
        await exploit.sendDeploy(exploitDeployer.getSender(), toNano('0.5'));
        
        // Run exploit steps
        const exploitAccount = blockchain.openContract(BaseContract.createFromConfig({
            deployer: serviceCounter.address,
            id: BigInt(`0x${beginCell()
                .storeUint(1, 4)    // contract type
                .storeAddress(exploit.address)
                .endCell().hash().toString('hex')}`),
        }, baseCode));
        let success = false;
        for (let i = 0; i < steps; i++) {
            await exploitDeployer.send({
                to: exploit.address,
                value: toNano('1'),
                body: beginCell()
                    .storeUint(OP.EXPLOIT_RUN, 32) // exploit::op::run
                    .storeUint(i, 64) // step number
                    .storeAddress(serviceCounter.address)
                    .storeAddress(coinMinter.address)
                    .storeAddress(ticketMinter.address)
                    .endCell(),
            });

            // Check if the exploit was successful by verifying if the solver is the exploit contract's account
            const currentSolver = await serviceCounter.getSolver();
            if (currentSolver !== null) {
                success = currentSolver.toString() === exploitAccount.address.toString();
                if (success) {
                    break;
                }
            }
        }
        let response: any = { success };
        if (success) {
            response.flag = FLAG;
        }
        
        res.json(response);
    } catch (error) {
        console.error('Error processing exploit:', error);
        res.status(500).json({ error: 'Failed to process exploit' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
