module challenge::sekai_lending {
    use challenge::collateral_coin::COLLATERAL_COIN;
    use challenge::sekai_coin::SEKAI_COIN;
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use std::debug;
    use sui::vec_map::{Self, VecMap};
    use std::u128::min;
    
    const LTV_RATIO: u64 = 80;
    const LIQUIDATION_THRESHOLD: u64 = 85;
    const MAX_BORROW_RATIO: u64 = 80;
    const LIQUIDATION_PENALTY: u64 = 10;
    const SEKAI_DECIMALS: u8 = 8;
    const COLLATERAL_DECIMALS: u8 = 9;

    const EInsufficientCollateral: u64 = 0;
    const EInsufficientLiquidity: u64 = 1;
    const ELiquidationThreshold: u64 = 2;
    const EUserNotAuthorized: u64 = 3;
    const EInvalidLTV: u64 = 4;
    const EPositionNotLiquidatable: u64 = 5;
    const EInsufficientRepayment: u64 = 6;

    public struct SEKAI_LENDING has key, store {
        id: UID,
        collateral_pool: Balance<COLLATERAL_COIN>,
        borrowed_pool: Balance<SEKAI_COIN>,
        total_collateral: u64,
        total_borrowed: u64,
        total_liquidations: u64,
        protocol_fees: u64,
        admin: address
    }

    public struct UserPosition has key, store {
        id: UID,
        collateral_amount: u64,
        borrowed_amount: u64,
        last_update: u64,
        is_liquidated: bool,
        liquidation_epoch: u64, 
        liquidation_reward: u64
    }

    public struct DepositEvent has copy, drop {
        user: address,
        collateral_amount: u64,
        total_collateral: u64
    }

    public struct BorrowEvent has copy, drop {
        user: address,
        borrow_amount: u64,
        collateral_used: u64,
    }

    public struct RepayEvent has copy, drop {
        user: address,
        repay_amount: u64,
        remaining_debt: u64
    }

    public struct WithdrawEvent has copy, drop {
        user: address,
        withdraw_amount: u64,
        remaining_collateral: u64
    }

    public struct LiquidateEvent has copy, drop {
        liquidator: address,
        collateral_liquidated: u64,
        debt_repaid: u64,
        liquidator_reward: u64
    }


    public fun create(collateral_coin: Coin<COLLATERAL_COIN>, sekai_coin: Coin<SEKAI_COIN>, ctx: &mut TxContext): SEKAI_LENDING {
        SEKAI_LENDING {
            id: object::new(ctx),
            collateral_pool: coin::into_balance(collateral_coin),
            borrowed_pool: coin::into_balance(sekai_coin),
            total_collateral: 0,
            total_borrowed: 0,
            total_liquidations: 0,
            protocol_fees: 0,
            admin: tx_context::sender(ctx)
        }
    }

    public fun add_liquidity(
        self: &mut SEKAI_LENDING,
        coins: Coin<SEKAI_COIN>,
        ctx: &mut TxContext
    ) {
        let coins_balance = coin::into_balance(coins);
        balance::join(&mut self.borrowed_pool, coins_balance);
    }

    public fun remove_liquidity(
        self: &mut SEKAI_LENDING,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<SEKAI_COIN> {
        assert!(tx_context::sender(ctx) == self.admin, EUserNotAuthorized);
        let balance = balance::split(&mut self.borrowed_pool, amount);
        coin::from_balance(balance, ctx)
    }

    public fun remove_collateral(
        self: &mut SEKAI_LENDING,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<COLLATERAL_COIN> {
        assert!(tx_context::sender(ctx) == self.admin, EUserNotAuthorized);
        let balance = balance::split(&mut self.collateral_pool, amount);
        coin::from_balance(balance, ctx)
    }

    public fun open_position(self: &mut SEKAI_LENDING, ctx: &mut TxContext): UserPosition {
        UserPosition {
            id: object::new(ctx),
            collateral_amount: 0,
            borrowed_amount: 0,
            last_update: tx_context::epoch(ctx),
            is_liquidated: false,
            liquidation_epoch: 0,
            liquidation_reward: 0
        }
    }

    public fun deposit_collateral(
        self: &mut SEKAI_LENDING,
        position: &mut UserPosition,
        collateral: Coin<COLLATERAL_COIN>,
        ctx: &mut TxContext
    ) {
        deposit_collateral_internal(self, ctx.sender(), position, collateral, ctx)
    }

    public fun deposit_collateral_for(
        self: &mut SEKAI_LENDING,
        user: address,
        position: &mut UserPosition,
        collateral: Coin<COLLATERAL_COIN>,
        ctx: &mut TxContext
    ) {
        deposit_collateral_internal(self, user, position, collateral, ctx)
    }

    fun deposit_collateral_internal(
        self: &mut SEKAI_LENDING,
        user: address,
        position: &mut UserPosition,
        collateral: Coin<COLLATERAL_COIN>,
        ctx: &mut TxContext
    ) {
        let collateral_amount = coin::value(&collateral);

        let collateral_balance = coin::into_balance(collateral);
        balance::join(&mut self.collateral_pool, collateral_balance);

        position.collateral_amount = position.collateral_amount + collateral_amount;
        position.last_update = tx_context::epoch(ctx);

        self.total_collateral = self.total_collateral + collateral_amount;

        sui::event::emit(DepositEvent {
            user,
            collateral_amount,
            total_collateral: self.total_collateral
        });
    }

    public fun max_borrow_amount(
        self: &mut SEKAI_LENDING,
        position: &mut UserPosition
    ): u128 {
        min(
            ((convert_decimal(position.collateral_amount, COLLATERAL_DECIMALS, SEKAI_DECIMALS) * LTV_RATIO) / 100) as u128,
            (self.borrowed_pool.value() * MAX_BORROW_RATIO / 100) as u128
        )
    }

    public fun borrow_coin(
        self: &mut SEKAI_LENDING,
        position: &mut UserPosition,
        borrow_amount: u64,
        ctx: &mut TxContext
    ): Coin<SEKAI_COIN> {
        let user = tx_context::sender(ctx);
        assert!(!position.is_liquidated, EUserNotAuthorized);

        let max_borrow = min(
            ((convert_decimal(position.collateral_amount, COLLATERAL_DECIMALS, SEKAI_DECIMALS) * LTV_RATIO) / 100) as u128,
            (self.borrowed_pool.value() * MAX_BORROW_RATIO / 100) as u128
        );

        assert!(borrow_amount <= max_borrow as u64, EInsufficientCollateral);

        position.borrowed_amount = position.borrowed_amount + borrow_amount;
        position.last_update = tx_context::epoch(ctx);

        let borrowed_coins = coin::from_balance(balance::split(&mut self.borrowed_pool, borrow_amount), ctx);

        self.total_borrowed = self.total_borrowed + borrow_amount;


        sui::event::emit(BorrowEvent {
            user,
            borrow_amount,
            collateral_used: position.collateral_amount,
        });

        borrowed_coins
    }

    public fun repay_loan(
        self: &mut SEKAI_LENDING,
        repayment: Coin<SEKAI_COIN>,
        position: &mut UserPosition,
        ctx: &mut TxContext
    ) {
        let user = tx_context::sender(ctx);
        
        let repayment_amount = coin::value(&repayment);
        
        assert!(self.total_borrowed >= repayment_amount, EInsufficientRepayment);
        
        balance::join(&mut self.borrowed_pool, coin::into_balance(repayment));

        position.borrowed_amount = position.borrowed_amount - repayment_amount;
        position.last_update = tx_context::epoch(ctx);

        self.total_borrowed = self.total_borrowed - repayment_amount;

        sui::event::emit(RepayEvent {
            user,
            repay_amount: repayment_amount,
            remaining_debt: position.borrowed_amount
        });
    }

    public fun withdraw_collateral(
        self: &mut SEKAI_LENDING,
        withdraw_amount: u64,
        position: &mut UserPosition,
        ctx: &mut TxContext
    ): Coin<COLLATERAL_COIN> {
        let user = tx_context::sender(ctx);
        
        assert!(!position.is_liquidated, EUserNotAuthorized);
        
        let max_borrow_amount = (convert_decimal(position.collateral_amount, COLLATERAL_DECIMALS, SEKAI_DECIMALS) - convert_decimal(withdraw_amount, COLLATERAL_DECIMALS, SEKAI_DECIMALS)) * LTV_RATIO / 100;
        assert!(position.borrowed_amount <= max_borrow_amount, EInvalidLTV);
        
        position.collateral_amount = position.collateral_amount - withdraw_amount;
        position.last_update = tx_context::epoch(ctx);
        
        let withdrawn_balance = balance::split(&mut self.collateral_pool, withdraw_amount);
        let withdrawn_coins = coin::from_balance(withdrawn_balance, ctx);

        self.total_collateral = self.total_collateral - withdraw_amount;

        sui::event::emit(WithdrawEvent {
            user,
            withdraw_amount,
            remaining_collateral: position.collateral_amount
        });

        withdrawn_coins
    }

    #[allow(lint(self_transfer))]
    public fun liquidate_position(
        self: &mut SEKAI_LENDING,
        position: &mut UserPosition,
        repayment: Coin<SEKAI_COIN>,
        ctx: &mut TxContext
    ) {
        assert!(!position.is_liquidated, EPositionNotLiquidatable);
        
        let ltv = position.borrowed_amount * 100 / convert_decimal(position.collateral_amount, COLLATERAL_DECIMALS, SEKAI_DECIMALS);
        let protocol_ltv = self.total_borrowed * 100 / convert_decimal(self.collateral_pool.value(), COLLATERAL_DECIMALS, SEKAI_DECIMALS);
        assert!(ltv > LIQUIDATION_THRESHOLD || protocol_ltv > LIQUIDATION_THRESHOLD, ELiquidationThreshold);

        
        let liquidator = tx_context::sender(ctx);
        let repayment_amount = coin::value(&repayment);
        assert!(repayment_amount >= position.borrowed_amount, EInsufficientRepayment);
        
        let debt_to_repay = position.borrowed_amount;
        let collateral_to_liquidate = position.collateral_amount;
        let protocol_fee = (collateral_to_liquidate * LIQUIDATION_PENALTY) / 100;
        
        let liquidator_reward = collateral_to_liquidate - protocol_fee;
        
        balance::join(&mut self.borrowed_pool, coin::into_balance(repayment));
        
        position.liquidation_epoch = tx_context::epoch(ctx);
        position.is_liquidated = true;
        position.liquidation_reward = liquidator_reward;
        position.collateral_amount = 0;
        position.borrowed_amount = 0;
        

        self.protocol_fees = self.protocol_fees + protocol_fee; 
        self.total_collateral = self.total_collateral - collateral_to_liquidate;
        self.total_borrowed = self.total_borrowed - debt_to_repay;
        self.total_liquidations = self.total_liquidations + 1;

        sui::event::emit(LiquidateEvent {
            liquidator,
            collateral_liquidated: collateral_to_liquidate,
            debt_repaid: debt_to_repay,
            liquidator_reward
        });
    }

    public fun claim_liquidation_reward(
        self: &mut SEKAI_LENDING,
        position: &mut UserPosition,
        ctx: &mut TxContext
    ): Coin<COLLATERAL_COIN> {
        let reward = position.liquidation_reward;
        position.liquidation_reward = 0;
        let reward_balance = balance::split(&mut self.collateral_pool, reward);
        let reward_coins = coin::from_balance(reward_balance, ctx);
        reward_coins
    }

    public fun withdraw_protocol_fees(
        self: &mut SEKAI_LENDING,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<COLLATERAL_COIN> {
        assert!(tx_context::sender(ctx) == self.admin, EUserNotAuthorized);
        
        assert!(amount <= self.protocol_fees, EInsufficientLiquidity);
        
        let fee_balance = balance::split(&mut self.collateral_pool, amount);
        let fee_coins = coin::from_balance(fee_balance, ctx);
        
        self.protocol_fees = self.protocol_fees - amount;
        
        fee_coins
    }

    public fun convert_decimal(amount: u64, source_decimals: u8, target_decimals: u8): u64 {
        if (source_decimals > target_decimals) {
            amount / 10u64.pow(source_decimals - target_decimals)
        } else {
            amount * 10u64.pow(target_decimals - source_decimals)
        }
    }
} 