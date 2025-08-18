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
        await writeFile(path.join(auto, 'arcade_machine_code.fc'), `;; auto-generated from arcade_machine.fc\ncell arcade_machine_code() asm "B{${code.toBoc().toString('hex')}} B>boc PUSHREF";\n`);
    },
    targets: ['contracts/arcade_machine.fc'],
};