#pragma once
#include <cstdint>
#include <stdexcept>
#include <unordered_map>

namespace msvc {
    enum struct ModuleID : std::uint32_t {
        CL = 0x6a5c1315,
        C1XX = 0xc219368c,
        C2 = 0x117baffd,
    };

    struct Module {
    public:
        ModuleID id;
        std::uintptr_t base;
    };

    inline /* constinit */ struct Context {
        std::unordered_map<ModuleID, Module> modules;

        [[nodiscard]] Module& emplace_module(const ModuleID id, const std::uintptr_t base) {
            auto& it = modules[id];
            it.id = id;
            it.base = base;
            return it;
        }
    } ctx = {};

    inline std::uintptr_t base(const ModuleID id) {
        auto it = ctx.modules.find(id);
        if (it == std::end(ctx.modules)) {
            throw std::out_of_range("");
        }

        return it->second.base;
    }
} // namespace msvc
