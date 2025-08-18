#!/usr/bin/env python3
from ctf_launchers import PwnChallengeLauncher, current_challenge
from ctf_launchers.types import ChallengeContract
from ctf_server.types import UserData, get_player_account, get_privileged_web3, LaunchAnvilInstanceArgs
from foundry.anvil import anvil_set_balance


class Launcher(PwnChallengeLauncher):
    def get_anvil_instances(self) -> dict[str, LaunchAnvilInstanceArgs]:
        return {
            'main': self.get_anvil_instance(
                gas_limit=100_000_000,
            ),
        }

    def deploy(self, user_data: UserData, mnemonics: dict[str, str]) -> list[ChallengeContract]:
        res = super().deploy(user_data, mnemonics)
        web3 = get_privileged_web3(user_data, 'main')
        anvil_set_balance(web3, get_player_account(mnemonics['main']).address, int(1.1 * 10**18))
        return res


current_challenge.bind(Launcher(project_location='/challenge/project'))


if __name__ == '__main__':
    current_challenge.run()
