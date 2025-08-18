#pragma once
#include <cstdint>
#include <shared/msvc/context.hpp>
#include <shared/msvc/structs.hpp>
#include <string>

namespace callbacks {
    void on_module_load(const msvc::Module& mod);
    void on_module_load(const std::wstring_view module_path, const std::uintptr_t base);
    void visit(const msvc::tagFUNC* func);
} // namespace callbacks