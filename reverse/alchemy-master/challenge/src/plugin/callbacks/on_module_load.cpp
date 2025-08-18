#include "callbacks.hpp"
#include <hooks/hooks.hpp>
#include <util/hooks.hpp>

namespace callbacks {
    void on_module_load(const msvc::Module& mod) {
        switch (mod.id) {
        case msvc::ModuleID::CL:
            /// Verbose
            //*reinterpret_cast<int*>(mod.base + 0xA3F64) = 1;
            break;

        case msvc::ModuleID::C1XX:
            break;

        case msvc::ModuleID::C2:
            util::create_hook(mod.base + 0xD5AA0, hooks::ReadFunction, &hooks::original::ReadFunction);
            break;
        }
    }

    void on_module_load(const std::wstring_view module_path, const std::uintptr_t base) {
        if (module_path.contains(L"c1xx.dll")) {
            on_module_load(msvc::ctx.emplace_module(msvc::ModuleID::C1XX, base));
            return;
        }

        if (module_path.contains(L"c2.dll")) {
            on_module_load(msvc::ctx.emplace_module(msvc::ModuleID::C2, base));
            return;
        }
    }
} // namespace callbacks
