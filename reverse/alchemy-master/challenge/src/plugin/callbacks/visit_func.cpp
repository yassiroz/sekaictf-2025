#include "callbacks.hpp"
#include <format>
#include <mutex>
#include <shared/game/game.hpp>

// #define DEBUG_PRINT

namespace callbacks {
    void visit(const msvc::tagFUNC* func) {
        if (func->tuple_container == nullptr || //
            func->tuple_container->inner == nullptr) {
            return;
        }

        auto tuple = func->tuple_container->inner->first;
        while (tuple != nullptr && //
               tuple->internal_node_kind != msvc::TupleInternalKind::BeginCompoundStmt) {
            tuple = tuple->next;
        }

        if (tuple == nullptr) {
            return;
        }

        std::size_t i = 0;
        do {
            i++;
            const auto result = game::storage.try_react(tuple->kind);

#if defined(DEBUG_PRINT)
            static std::mutex mtx;
            std::lock_guard lock(mtx);

            static std::unordered_map<msvc::TupleKind, std::string_view> kTupleKindNames = {
                {msvc::TupleKind::FunctionPrologue, "FunctionPrologue"},
                {msvc::TupleKind::BeginEpilogue, "BeginEpilogue"},
                {msvc::TupleKind::FunctionEpilogue, "FunctionEpilogue"},
                {msvc::TupleKind::ScopeCleanup, "ScopeCleanup"},
                {msvc::TupleKind::ObjectInitializationStmt, "ObjectInitializationStmt"},
                {msvc::TupleKind::SimpleStmt, "SimpleStmt"},
                {msvc::TupleKind::DeclarationWithCastStmt, "DeclarationWithCastStmt"},
                {msvc::TupleKind::ComplexExprStmt, "ComplexExprStmt"},
                {msvc::TupleKind::ConditionalStmt, "ConditionalStmt"},
                {msvc::TupleKind::FunctionCallStmt, "FunctionCallStmt"},
                {msvc::TupleKind::ReturnStmt, "ReturnStmt"},
                {msvc::TupleKind::JumpOnFalse, "JumpOnFalse"},
                {msvc::TupleKind::Jump, "Jump"},
                {msvc::TupleKind::EH_Jump, "EH_Jump"},
                {msvc::TupleKind::EH_Setup, "EH_Setup"},
                {msvc::TupleKind::ThrowStmt, "ThrowStmt"},
                {msvc::TupleKind::EH_Rethrow, "EH_Rethrow"},
                {msvc::TupleKind::VirtualCallStmt, "VirtualCallStmt"},
                {msvc::TupleKind::DestructorEHBlock, "DestructorEHBlock"},
                {msvc::TupleKind::BeginTryBlock, "BeginTryBlock"},
                {msvc::TupleKind::BeginCatchBlock, "BeginCatchBlock"},
                {msvc::TupleKind::EndEHBlock, "EndEHBlock"},
                {msvc::TupleKind::BeginCompoundStmt, "BeginCompoundStmt"},
                {msvc::TupleKind::EndCompoundStmt, "EndCompoundStmt"},
            };

            auto get_or_unk = [](auto&& map, auto&& lhs) -> std::string {
                auto iter = map.find(lhs);
                if (iter == map.end()) {
                    return std::format("unknown_{:d}", static_cast<int>(lhs));
                }
                return iter->second.data();
            };
            std::string kind_name = get_or_unk(kTupleKindNames, tuple->kind);

            printf("[i=%lld] kind=%s", i, kind_name.c_str());
            if (result) {
                printf("\t\t\tstate: { ");
                for (std::size_t i = 0; i < game::kMaterialCount; ++i) {
                    printf("%lld", game::storage.qty(i));
                    if (i != game::kMaterialCount - 1) {
                        printf(", ");
                    }
                }
                printf("}");
            }
            printf("\n");
#else
            std::ignore = result;
#endif
        } while (tuple = tuple->next);

        if (game::storage.is_game_over()) {
            printf("Good job! Here is your flag: SEKAI{real_flag_is_on_remote}\n");
            std::exit(0);
        }
    }
} // namespace callbacks
