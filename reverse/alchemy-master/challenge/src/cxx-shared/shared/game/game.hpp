#pragma once
#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <string_view>
#include <unordered_map>

#include <shared/msvc/structs.hpp>

namespace game {
    enum struct AlchemyMaterialType : std::uint16_t {
        LEAD = 1 << 0,
        AETHER = 1 << 1,
        QUICKSILVER = 1 << 2,
        IRON = 1 << 3,
        WATER = 1 << 4,
        SALT = 1 << 5,
        SULFUR = 1 << 6,
        MATERIALS_COUNT = 7,
    };
    constexpr auto operator|(const AlchemyMaterialType lhs, const AlchemyMaterialType rhs) noexcept {
        return static_cast<AlchemyMaterialType>(std::to_underlying(lhs) | std::to_underlying(rhs));
    }

    constexpr std::size_t kMaterialCount = std::to_underlying(AlchemyMaterialType::MATERIALS_COUNT);
    constexpr std::size_t kMaxQuantity = 17000;
    constexpr std::array<std::size_t, kMaterialCount> kTargetQuantities = {
        333, 727, 353, 746, 433, 765, 361,
    };

    struct AlchemyReaction {
    public:
        msvc::TupleKind trigger;
        AlchemyMaterialType ingredients;
        AlchemyMaterialType product;
    };

    constexpr auto kReactions = std::to_array<AlchemyReaction>({
        {msvc::TupleKind::BeginCatchBlock, AlchemyMaterialType::LEAD | AlchemyMaterialType::WATER, AlchemyMaterialType::SULFUR},
        {msvc::TupleKind::SimpleStmt, AlchemyMaterialType::SULFUR | AlchemyMaterialType::WATER, AlchemyMaterialType::QUICKSILVER},
        {msvc::TupleKind::ThrowStmt, AlchemyMaterialType::QUICKSILVER | AlchemyMaterialType::SULFUR | AlchemyMaterialType::WATER,
         AlchemyMaterialType::AETHER},
        {msvc::TupleKind::EH_Rethrow, AlchemyMaterialType::IRON | AlchemyMaterialType::LEAD, AlchemyMaterialType::WATER},
        {msvc::TupleKind::FunctionCallStmt, AlchemyMaterialType::LEAD | AlchemyMaterialType::SULFUR, AlchemyMaterialType::IRON},
        {msvc::TupleKind::DestructorEHBlock, AlchemyMaterialType::IRON | AlchemyMaterialType::QUICKSILVER, AlchemyMaterialType::AETHER},
        {msvc::TupleKind::ReturnStmt, AlchemyMaterialType::LEAD | AlchemyMaterialType::WATER, AlchemyMaterialType::SALT},
        {msvc::TupleKind::BeginCompoundStmt, AlchemyMaterialType::SULFUR | AlchemyMaterialType::LEAD, AlchemyMaterialType::SALT},
        {msvc::TupleKind::BeginEpilogue, AlchemyMaterialType::WATER | AlchemyMaterialType::LEAD, AlchemyMaterialType::SALT},
    });

    inline constinit class AlchemyStorage {
    public:
        constexpr AlchemyStorage(): qty_{} {
            /// Initial values
            qty_[index(AlchemyMaterialType::LEAD)] = 1844;
            qty_[index(AlchemyMaterialType::WATER)] = 3004;
            qty_[index(AlchemyMaterialType::SULFUR)] = 2915;
        }

        bool add(AlchemyMaterialType t, std::size_t n = 1) {
            auto& q = qty_[index(t)];
            std::size_t new_q = std::min<std::size_t>(q + n, kMaxQuantity);
            bool saturated = new_q == kMaxQuantity && n > 0;
            q = new_q;
            return !saturated;
        }

        [[nodiscard]] bool has(AlchemyMaterialType t, std::size_t n = 1) const {
            return qty_[index(t)] >= n;
        }

        bool try_sub(AlchemyMaterialType t, std::size_t n = 1) {
            auto& q = qty_[index(t)];
            if (q < n) {
                return false;
            }
            q -= n;
            return true;
        }

        bool try_react(const AlchemyReaction& r) {
            if (!has_all(r.ingredients)) {
                return false;
            }
            consume(r.ingredients);
            add(r.product, 1);
            return true;
        }

        bool try_react(const std::size_t reaction_id) {
            return try_react(kReactions[reaction_id]);
        }

        bool try_react(const msvc::TupleKind kind) {
            for (auto& reaction : kReactions) {
                if (reaction.trigger != kind) {
                    continue;
                }

                return try_react(reaction);
            }
            return false;
        }

        [[nodiscard]] bool is_game_over() const noexcept {
            for (std::size_t i = 0; i < kMaterialCount; ++i) {
                if (qty_[i] != kTargetQuantities[i]) {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] std::size_t qty(const std::size_t i) const noexcept {
            return qty_[i];
        }

        [[nodiscard]] auto qtys() const {
            return qty_;
        }

    private:
        std::array<std::size_t, kMaterialCount> qty_;

        static constexpr std::size_t index(AlchemyMaterialType t) {
            return std::countr_zero(std::to_underlying(t));
        }

        bool has_all(AlchemyMaterialType mask) const {
            std::uint16_t bits = std::to_underlying(mask);
            for (std::size_t i = 0; i < kMaterialCount; ++i) {
                if ((bits & (1u << i)) && qty_[i] == 0) {
                    return false;
                }
            }
            return true;
        }

        void consume(AlchemyMaterialType mask) {
            std::uint16_t bits = std::to_underlying(mask);
            for (std::size_t i = 0; i < kMaterialCount; ++i) {
                if (bits & (1u << i)) {
                    --qty_[i];
                }
            }
        }
    } storage = {};
} // namespace game