module challenge::collateral_coin {
    use sui::coin::{Self, TreasuryCap};
    public struct COLLATERAL_COIN has drop {}

    fun init(witness: COLLATERAL_COIN, ctx: &mut TxContext) {
        let (treasury, metadata) = coin::create_currency(
            witness,
            9,
            b"COLLATERAL",
            b"COLLATERAL Coin",
            b"COLLATERAL Coin",
            option::none(),
            ctx,
        );
        transfer::public_freeze_object(metadata);
        transfer::public_transfer(treasury, ctx.sender());
    }

    #[test_only]
    public fun test_create_currency(ctx: &mut TxContext): TreasuryCap<COLLATERAL_COIN> {
        let (treasury, metadata) = coin::create_currency(
            COLLATERAL_COIN {},
            9,
            b"COLLATERAL",
            b"COLLATERAL Coin",
            b"COLLATERAL Coin",
            option::none(),
            ctx,
        );
        transfer::public_freeze_object(metadata);
        treasury
    }
}