#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>

#include <Windows.h>

int main(int argc, char* argv[]) {
    std::string line = "/Zi /nologo /c";
    for (std::size_t i = 1; i < argc; ++i) {
        const auto* arg = argv[i];
        line += ' ';
        line += arg;
    }

    char cur_path[_MAX_PATH + 1] = {0};
    GetModuleFileNameA(nullptr, cur_path, sizeof(cur_path));

    HANDLE dup_stdout, dup_stderr;
    const auto stdout_h = GetStdHandle(STD_OUTPUT_HANDLE);
    const auto stderr_h = GetStdHandle(STD_ERROR_HANDLE);

    auto dup = [&](HANDLE src, HANDLE& dst) [[msvc::forceinline]] {
        return DuplicateHandle(GetCurrentProcess(), src, GetCurrentProcess(), &dst, 0, TRUE, DUPLICATE_SAME_ACCESS);
    };

    if (!dup(stdout_h, dup_stdout) || !dup(stderr_h, dup_stderr)) {
        printf("unable to duplicate handles\n");
        return 1;
    }

    STARTUPINFOA si = {.cb = sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = dup_stdout;
    si.hStdError = dup_stderr;

#if 0
    const std::string_view cl_exe_path =
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.44.35207\\bin\\HostX64\\x64\\CL.exe";
#else
    const auto cl_exe_path = (std::filesystem::path(cur_path).parent_path() / "MSVC" / "14.44.35207" / "bin" / "HostX64" / "x64" / "CL.exe").string();
#endif

    BOOL created = CreateProcessA(cl_exe_path.data(), line.data(), NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    if (!created) {
        printf("unable to start cl.exe from %s\n", cl_exe_path.data());
        return 1;
    }
    CloseHandle(pi.hThread);

    const auto plugin = std::filesystem::path(cur_path).parent_path() / "plugin.dll";
    const auto plugin_str = plugin.string();
    if (!exists(plugin)) {
        printf("unable to find plugin at %s\n", plugin_str.c_str());
        return 1;
    }

    LPVOID mem = VirtualAllocEx(pi.hProcess, nullptr, plugin_str.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem == nullptr) {
        printf("unable to alloc mem\n");
        return 1;
    }

    if (!WriteProcessMemory(pi.hProcess, mem, plugin_str.data(), plugin_str.size() + 1, nullptr)) {
        printf("unable to write memory\n");
        return 1;
    }

    CreateRemoteThread(pi.hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), mem, 0, nullptr);
    WaitForSingleObject(pi.hProcess, INFINITE);
    return 0;
}
