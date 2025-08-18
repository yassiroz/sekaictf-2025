import { CompilerConfig } from '@ton/blueprint';
import { writeFile } from 'fs/promises';
import path from 'path';

export const compile: CompilerConfig = {
    lang: 'func',
    postCompileHook: async (code) => {
        const auto = path.join(__dirname, '..', 'contracts', 'bytecode');
        await writeFile(path.join(auto, 'base_contract_code.fc'), `;; auto-generated from base_contract.fc\ncell base_contract_code() asm "B{${code.toBoc().toString('hex')}} B>boc PUSHREF";\n`);
    },
    targets: ['contracts/base_contract.fc'],
};