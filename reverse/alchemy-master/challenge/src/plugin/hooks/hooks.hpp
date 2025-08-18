#pragma once
#include <cstdint>
#include <cstdio>
#include <set>
#include <source_location>
#include <string>

#include <Windows.h>

#include <callbacks/callbacks.hpp>
#include <minhook/MinHook.h>
#include <shared/msvc/context.hpp>
#include <shared/msvc/structs.hpp>

namespace hooks {
    namespace original {
        inline constinit decltype(&::LoadLibraryExW) LoadLibraryExW = nullptr;
        inline constinit msvc::tagFUNC* (*ReadFunction)(msvc::Symbol*) = nullptr;
    } // namespace original

    inline HMODULE LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
        const auto result = original::LoadLibraryExW(lpLibFileName, hFile, dwFlags);
        callbacks::on_module_load(lpLibFileName, reinterpret_cast<std::uintptr_t>(result));
        return result;
    }

    inline msvc::tagFUNC* ReadFunction(msvc::Symbol* sym) {
        auto result = original::ReadFunction(sym);
        callbacks::visit(result);
        return result;
    }
} // namespace hooks
