#include <stdio.h>
#include <stdint.h>
#include "nt.h"

struct CodeStatus {
	ULONGLONG key[2];
	BOOL encrypted;
};

struct PackerData {
	ULONG_PTR codeBegin;
	ULONG_PTR codeEnd;

	BOOL(WINAPI* IsDebuggerPresent)(VOID);
	BOOL(WINAPI* CheckRemoteDebuggerPresent)(HANDLE hProcess, PBOOL pbDebuggerPresent);
	BOOL(WINAPI* VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
	BOOL(WINAPI* TerminateProcess)(HANDLE hProcess, UINT uExitCode);
	PVOID(WINAPI* AddVectoredExceptionHandler)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
	HANDLE(WINAPI* GetCurrentProcess)(VOID);
	HMODULE(WINAPI* GetModuleHandleW)(LPCWSTR lpModuleName);
	NTSTATUS(*NtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
	NTSTATUS(*NtSetInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
};

#define STATIC_STORAGE_SIZE 65536
#define FNV_BASE 14695981039346656037ULL
#define FNV_PRIME 1099511628211ULL
#define KERNEL32_HASH 0xe14b18a7acf9c443
#define NTDLL_HASH 0xbb7bb9a74c2f14fb

#define VirtualAlloc_HASH 0xfa55e32c9d72a921
#define IsDebuggerPresent_HASH 0x7c566c5e497f0961
#define CheckRemoteDebuggerPresent_HASH 0xe3549a1b1e8d41e1
#define VirtualProtect_HASH 0xed1006223abbbd53
#define TerminateProcess_HASH 0x911cd097f785b8d9
#define GetCurrentProcess_HASH 0x426d71ab8c084ce5
#define GetModuleHandleW_HASH 0x637416f7171ea26
#define RtlAddVectoredExceptionHandler_HASH 0xecfb09068e3b6ae5
#define NtQueryInformationProcess_HASH 0x32ca9e4b50ffedaa
#define NtSetInformationThread_HASH 0x84db084a3c7eb621

PackerData *pd;
char staticStorage[STATIC_STORAGE_SIZE];
struct CodeStatus codeStatus[1024];

__declspec (code_seg(",text"))
FORCEINLINE uint64_t HashString(const char* buf) {
	uint64_t h = FNV_BASE;

	for (auto p = buf; *p != 0; p++) {
		h ^= *p;
		h *= FNV_PRIME;
	}

	return h;
}

__declspec (code_seg(",text"))
FORCEINLINE int ToLower(int ch) {
	if (ch >= 'A' && ch <= 'Z') {
		return ch + 32;
	}
	else {
		return ch;
	}
}

__declspec (code_seg(",text"))
FORCEINLINE uint64_t HashWStringForceLower(const wchar_t* buf) {
	uint64_t h = FNV_BASE;

	for (auto p = buf; *p != 0; p++) {
		wchar_t c = ToLower(*p);
		h ^= c;
		h *= FNV_PRIME;
	}

	return h;
}

__declspec (code_seg(",text"))
FORCEINLINE BOOL SetPageEncrypted(ULONG_PTR idx, BOOL encrypted) {
	if (codeStatus[idx].encrypted == encrypted) {
		return FALSE;
	}

	ULONGLONG *base = (ULONGLONG *)(pd->codeBegin + idx * 0x1000);
	DWORD oldProtect;
	pd->VirtualProtect((PVOID)base, 0x1000, PAGE_READWRITE, &oldProtect);

	for (int off = 0; off < 0x1000 / 8; off += 2) {
		base[off] ^= codeStatus[idx].key[0];
		base[off + 1] ^= codeStatus[idx].key[1];
	}

	codeStatus[idx].encrypted = encrypted;
	pd->VirtualProtect((PVOID)base, 0x1000, encrypted ? PAGE_NOACCESS : PAGE_EXECUTE_READ, &oldProtect);

	return TRUE;
}

__declspec (code_seg(",text"))
FORCEINLINE PVOID GetPEB() {
#if defined(_M_X64)
	return (PVOID)__readgsqword(0x60);
#elif defined(_M_IX86)
	return (PVOID)__readfsdword(0x30);
#else
#error Unsupported architecture
#endif
}

__declspec (code_seg(",text"))
FORCEINLINE void CheckDebugger() {
	if (pd->IsDebuggerPresent()) {
		pd->TerminateProcess(pd->GetCurrentProcess(), 0);
	}

	BOOL debuggerPresent;
	if (pd->CheckRemoteDebuggerPresent(pd->GetCurrentProcess(), &debuggerPresent) && debuggerPresent) {
		pd->TerminateProcess(pd->GetCurrentProcess(), 0);
	}

	PEB* peb = (PEB*)GetPEB();
	if (peb->BeingDebugged) {
		pd->TerminateProcess(pd->GetCurrentProcess(), 0);
	}

	DWORD_PTR debugPort = 0;
	if (pd->NtQueryInformationProcess(pd->GetCurrentProcess(), ProcessDebugPort, &debugPort, sizeof(debugPort), NULL) == STATUS_SUCCESS && debugPort != 0) {
		pd->TerminateProcess(pd->GetCurrentProcess(), 0);
	}
}

__declspec (code_seg(",text"))
FORCEINLINE bool AntiDebug() {
	NTSTATUS status = pd->NtSetInformationThread(NtCurrentThread, ThreadHideFromDebugger, NULL, 0);
	return status >= 0;
}

__declspec (code_seg(",text"))
LONG ExceptionHandler(struct _EXCEPTION_POINTERS* ExceptionInfo) {
	CheckDebugger();

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
		ULONG_PTR addr = (ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress;
		if (pd->codeBegin <= addr && addr < pd->codeEnd) {
			if (ExceptionInfo->ExceptionRecord->ExceptionInformation[0] == 1) {
				return EXCEPTION_EXECUTE_HANDLER;
			}

			if (!SetPageEncrypted((addr - pd->codeBegin) / 0x1000, false))
				SetPageEncrypted((addr - pd->codeBegin) / 0x1000 + 1, false);

			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	return EXCEPTION_EXECUTE_HANDLER;
}

__declspec (code_seg(",text"))
FORCEINLINE HMODULE FindModule(uint64_t hash) {
	PEB* peb = (PEB*)GetPEB();
	LIST_ENTRY* head = &peb->Ldr->InLoadOrderModuleList;
	for (LIST_ENTRY* entry = head->Flink; entry != head; entry = entry->Flink) {
		LDR_DATA_TABLE_ENTRY* mod = (LDR_DATA_TABLE_ENTRY*)entry;
		if (mod->BaseDllName.Buffer) {
			if (HashWStringForceLower(mod->BaseDllName.Buffer) == hash) {
				return (HMODULE)mod->DllBase;
			}
		}
	}
	return nullptr;
}

__declspec (code_seg(",text"))
FORCEINLINE FARPROC GetExportByName(HMODULE module, uint64_t hash) {
	auto dos = (PIMAGE_DOS_HEADER)module;
	auto nt = (PIMAGE_NT_HEADERS)((BYTE*)module + dos->e_lfanew);
	auto expDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!expDir->VirtualAddress) return nullptr;
	auto exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)module + expDir->VirtualAddress);
	auto names = (DWORD*)((BYTE*)module + exp->AddressOfNames);
	auto funcs = (DWORD*)((BYTE*)module + exp->AddressOfFunctions);
	auto ords = (WORD*)((BYTE*)module + exp->AddressOfNameOrdinals);
	for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
		const char* funcName = (const char*)module + names[i];
		if (HashString(funcName) == hash) {
			return (FARPROC)((BYTE*)module + funcs[ords[i]]);
		}
	}
	return nullptr;
}

__declspec (code_seg(",text"))
FORCEINLINE
uint32_t Rand(uint32_t* state) {
	return *state = (uint64_t)*state * 48271 % 0x7fffffff;
}

__declspec (noinline, code_seg(",text"))
void Initialize() {
	HMODULE k32 = FindModule(KERNEL32_HASH);

	LPVOID(WINAPI * pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
	*(FARPROC*)&pVirtualAlloc = GetExportByName(k32, VirtualAlloc_HASH);

	pd = (PackerData*)pVirtualAlloc(NULL, sizeof(PackerData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	*(FARPROC*)&pd->IsDebuggerPresent = GetExportByName(k32, IsDebuggerPresent_HASH);
	*(FARPROC*)&pd->CheckRemoteDebuggerPresent = GetExportByName(k32, CheckRemoteDebuggerPresent_HASH);
	*(FARPROC*)&pd->VirtualProtect = GetExportByName(k32, VirtualProtect_HASH);
	*(FARPROC*)&pd->TerminateProcess = GetExportByName(k32, TerminateProcess_HASH);
	*(FARPROC*)&pd->GetCurrentProcess = GetExportByName(k32, GetCurrentProcess_HASH);
	*(FARPROC*)&pd->GetModuleHandleW = GetExportByName(k32, GetModuleHandleW_HASH);

	HMODULE ntdll = FindModule(NTDLL_HASH);
	*(FARPROC*)&pd->AddVectoredExceptionHandler = GetExportByName(ntdll, RtlAddVectoredExceptionHandler_HASH);
	*(FARPROC*)&pd->NtQueryInformationProcess = GetExportByName(ntdll, NtQueryInformationProcess_HASH);
	*(FARPROC*)&pd->NtSetInformationThread = GetExportByName(ntdll, NtSetInformationThread_HASH);

	AntiDebug();

	HANDLE h = pd->GetModuleHandleW(NULL);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)h;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)h + dosHeader->e_lfanew);

	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

	for (auto i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
		if (sectionHeader[i].Name[0] == '.' && sectionHeader[i].Name[1] == 't' && sectionHeader[i].Name[2] == 'e' && sectionHeader[i].Name[3] == 'x' && sectionHeader[i].Name[4] == 't' && sectionHeader[i].Name[5] == '\x00') {
			ULONGLONG alignedSize = (sectionHeader[i].Misc.VirtualSize + 0xFFF) & ~0xFFF;
			pd->codeBegin = (ULONG_PTR)h + sectionHeader[i].VirtualAddress;
			pd->codeEnd = pd->codeBegin + alignedSize;
			uint32_t state = 0x4b534a50;

			for (int i = 0; i < alignedSize / 0x1000; ++i) {
				codeStatus[i].key[0] = ((ULONGLONG)Rand(&state) << 32) | Rand(&state);
				codeStatus[i].key[1] = ((ULONGLONG)Rand(&state) << 32) | Rand(&state);
				SetPageEncrypted(i, true);
			}

			break;
		}
	}

	DWORD oldProtect;
	pd->VirtualProtect(pd, sizeof(PackerData), PAGE_READONLY, &oldProtect);
	pd->AddVectoredExceptionHandler(0, ExceptionHandler);
}

class X {
public:
	X() {
		Initialize();
	}
} x;

int main() {
	FILE* f = NULL;
	fopen_s(&f, "data.txt", "rb");
	if (f == NULL) {
		printf("Contact support\n");
		return 0;
	}
	int i = 0, k = 0;
	char key[4] = { 'P', 'J', 'S', 'K' };
	while (!feof(f)) {
		staticStorage[i++] = fgetc(f) ^ key[k];
		k = (k + 1) % 4;
	}
	FILE* o = NULL;
	fopen_s(&f, "output.txt", "wb");
	if (f == NULL) {
		printf("Contact support\n");
		return 0;
	}
	fwrite(staticStorage, 1, i, f);
}
