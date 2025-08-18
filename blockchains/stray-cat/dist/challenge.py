#!/usr/bin/env python3
from Crypto.Hash import keccak
from pyrlp import decode  # https://github.com/SamuelHaidu/simple-rlp
from web3 import Web3

from ctf_launchers import PwnChallengeLauncher, current_challenge
from ctf_launchers.types import ChallengeContract
from ctf_server.types import LaunchAnvilInstanceArgs


k = keccak.new(digest_bits=256)
k.update(b'Purr()')
TARGET = k.digest()


class Launcher(PwnChallengeLauncher):
    def get_anvil_instances(self) -> dict[str, LaunchAnvilInstanceArgs]:
        # This challenge uses a "custom" foundry build:
        #   https://github.com/es3n1n/foundry/commit/21da3334659c2e54ea0680192daa0883935a473d
        return {
            'main': self.get_anvil_instance(
                image='ghcr.io/es3n1n/foundry:latest',
                extra_allowed_methods=['debug_getRawReceipts'],
            ),
        }

    def is_solved(
        self,
        web3: Web3,
        contracts: list[ChallengeContract],
        dynamic_fields: dict[str, str],
        team: str,
    ) -> bool:
        block_num = dynamic_fields.get('block', 'latest')
        if not block_num.startswith('0x'):
            block_num = f'0x{block_num}'
        receipts = web3.provider.make_request(
            'debug_getRawReceipts',  # type: ignore[arg-type]
            [block_num],
        )

        if 'error' in receipts:
            return False

        recs = receipts['result']
        if not recs:
            return False

        try:
            rec = bytes.fromhex(recs[0].replace('0x', ''))
            _tx_type, rlp = rec[:1], rec[1:]
            receipt = decode(rlp)

            if receipt[0] != b'\x01':
                return False

            if len(receipt[2]) != 256:
                return False

            logs = [x for x in receipt[3] if int.from_bytes(x[0], 'big') == int(contracts[0]['address'], 16)]

            if not logs:
                return False

            log = logs[0]
            if log[2] != b'':
                return False

            if log[1] != [TARGET]:
                return False
        except Exception:
            return False
        return True


current_challenge.bind(Launcher(project_location='/challenge/project', dynamic_fields=['block']))


if __name__ == '__main__':
    current_challenge.run()
