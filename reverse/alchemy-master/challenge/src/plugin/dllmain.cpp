#include <cstdint>
#include <cstdio>
#include <Windows.h>

#include "callbacks/callbacks.hpp"
#include "hooks/hooks.hpp"
#include "shared/msvc/context.hpp"
#include "util/hooks.hpp"

namespace {
    void entry() try {
        const auto cl_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA("CL.exe"));
        callbacks::on_module_load(msvc::ctx.emplace_module(msvc::ModuleID::CL, cl_base));
        util::create_hook(::LoadLibraryExW, hooks::LoadLibraryExW, &hooks::original::LoadLibraryExW);
    } catch (std::exception& err) {
        printf("FATAL ERROR: %s\n", err.what());
        std::exit(1);
    }
} // namespace

EXTERN_C BOOL __stdcall DllMain(void*, std::uint32_t call_reason, void*) {
    if (call_reason != DLL_PROCESS_ATTACH) {
        return TRUE;
    }

    entry();
    const auto NtResumeProcess = reinterpret_cast<LONG(NTAPI*)(HANDLE)>(GetProcAddress(LoadLibraryA("ntdll"), "NtResumeProcess"));
    NtResumeProcess(reinterpret_cast<HANDLE>(-1));
    return TRUE;
}
