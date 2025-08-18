import { CompilerConfig } from '@ton/blueprint';
import { compile as compileFunc } from '@ton/blueprint';
import { writeFile } from 'fs/promises';
import path from 'path';

export const compile: CompilerConfig = {
    lang: 'func',
    preCompileHook: async () => {
        await compileFunc('BaseContract');
    },
    postCompileHook: async (code) => {
        const auto = path.join(__dirname, '..', 'contracts', 'bytecode');
        await writeFile(path.join(auto, 'account_code.fc'), `;; auto-generated from account.fc\ncell account_code() asm "B{${code.toBoc().toString('hex')}} B>boc PUSHREF";\n`);
    },
    targets: ['contracts/account.fc'],
};