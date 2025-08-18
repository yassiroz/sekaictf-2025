module challenge::challenge {
    use challenge::sekai_coin::SEKAI_COIN;
    use challenge::collateral_coin::COLLATERAL_COIN;
    use challenge::sekai_lending::{Self, SEKAI_LENDING, UserPosition};
    use sui::coin::{Self, TreasuryCap, Coin};
    use sui::balance::{Self, Balance};
    use std::type_name;
    use std::string::{Self, String};

    const INITIAL_COLLATERAL: u64 = 100 * 1_000_000_000;
    const INITIAL_SEKAI: u64 = 100 * 1_00_000_000;
    const INITIAL_CLAIM: u64 = 10 * 1_000_000_000;

    const ENotSolved: u64 = 0;

    public struct Challenge has key, store {
        id: UID,
        sekai_lending: SEKAI_LENDING,
        sekai_donation: Balance<SEKAI_COIN>,
        collateral_donation: Balance<COLLATERAL_COIN>,
        claim: Balance<COLLATERAL_COIN>,
        user_positions: vector<UserPosition>
    }
    
    public fun get_sekai_lending(challenge: &Challenge): &SEKAI_LENDING {
        &challenge.sekai_lending
    }

    public fun get_sekai_lending_mut(challenge: &mut Challenge): &mut SEKAI_LENDING {
        &mut challenge.sekai_lending
    } 

    public fun create(sekai_treasury: &mut TreasuryCap<SEKAI_COIN>, collateral_treasury: &mut TreasuryCap<COLLATERAL_COIN>, ctx: &mut TxContext) {
        let claim = coin::into_balance(coin::mint(collateral_treasury, INITIAL_CLAIM, ctx));
        let collateral_coin = coin::mint(collateral_treasury, INITIAL_COLLATERAL, ctx);
        let sekai_coin = coin::mint(sekai_treasury, INITIAL_SEKAI, ctx);
        let sekai_lending = sekai_lending::create(collateral_coin, sekai_coin, ctx);
        let challenge = Challenge {
            id: object::new(ctx),
            sekai_lending,
            sekai_donation: balance::zero(),
            collateral_donation: balance::zero(),
            claim,
            user_positions: vector::empty()
        };
        transfer::public_share_object(challenge);
    }

    #[allow(lint(self_transfer))]
    public fun claim(challenge: &mut Challenge, ctx: &mut TxContext): Coin<COLLATERAL_COIN> {
        coin::from_balance(balance::split(&mut challenge.claim, INITIAL_CLAIM), ctx)
    }
    
    public fun donate_sekai(challenge: &mut Challenge, coin: Coin<SEKAI_COIN>) {
        balance::join(&mut challenge.sekai_donation, coin::into_balance(coin));
    }

    public fun donate_collateral(challenge: &mut Challenge, coin: Coin<COLLATERAL_COIN>) {
        balance::join(&mut challenge.collateral_donation, coin::into_balance(coin));
    }

    public fun is_solved(challenge: &Challenge) {
        assert!(balance::value(&challenge.sekai_donation) == INITIAL_SEKAI * 8 / 10 && 
        balance::value(&challenge.collateral_donation) == INITIAL_COLLATERAL, ENotSolved);
    }
}