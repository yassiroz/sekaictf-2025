module challenge::sekai_coin {
    use sui::coin::{Self, TreasuryCap};
    public struct SEKAI_COIN has drop {}

    fun init(witness: SEKAI_COIN, ctx: &mut TxContext) {
        let (treasury, metadata) = coin::create_currency(
            witness,
            8,
            b"SEKAI",
            b"SEKAI Coin",
            b"SEKAI Coin",
            option::none(),
            ctx,
        );
        transfer::public_freeze_object(metadata);
        transfer::public_transfer(treasury, ctx.sender());
    }

    #[test_only]
    public fun test_create_currency(ctx: &mut TxContext): TreasuryCap<SEKAI_COIN> {
        let (treasury, metadata) = coin::create_currency(
            SEKAI_COIN {},
            8,
            b"SEKAI",
            b"SEKAI Coin",
            b"SEKAI Coin",
            option::none(),
            ctx,
        );
        transfer::public_freeze_object(metadata);
        treasury
    }
}