#pragma once
#include <minhook/MinHook.h>
#include <mutex>
#include <thread>

namespace util {
    namespace detail {
        inline void init_minhook() {
            static std::once_flag fl;
            std::call_once(fl, []() -> void {
                if (MH_Initialize() != MH_STATUS::MH_OK) {
                    throw std::runtime_error("unable to init");
                }
            });
        }
    } // namespace detail

    template <typename Ty, typename Ty2>
    void create_hook(Ty2 func, Ty* hook, Ty** original_ptr) {
        detail::init_minhook();

        void* func_v;
        if constexpr (std::is_same_v<Ty2, void*>) {
            func_v = func;
        } else if constexpr (std::convertible_to<Ty2, void*>) {
            func_v = static_cast<void*>(func);
        } else {
            func_v = reinterpret_cast<void*>(func);
        }

        if (MH_CreateHook(func_v, hook, reinterpret_cast<void**>(original_ptr)) != MH_STATUS::MH_OK) {
            throw std::runtime_error("unable to init 2");
        }

        MH_EnableHook(func_v);
    }
} // namespace util