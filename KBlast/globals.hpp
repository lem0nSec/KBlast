/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once

#include <Windows.h>
#include <winternl.h>
#include <wincrypt.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <shlwapi.h>
#include <stdio.h>

#include "Kblast_device.hpp"
#include "Kblast_string.hpp"
#include "Kblast_service.hpp"
#include "Kblast_process.hpp"
#include "../KBlaster/offsets.hpp"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Shlwapi.lib")

#define UNICODE 1

#define PRINT_ERR_FULL(fmt, ...) do {															\
				DWORD LastError = GetLastError();												\
				wprintf(L"[-] " TEXT(__FUNCTION__) L" ( 0x%08X ) : " fmt L"\n", LastError);		\
			} while (0)

#define PRINT_ERR(...) (wprintf(L"[-] Error : " __VA_ARGS__ L"\n"))
#define PRINT_SUCC(...) (wprintf(L"[+] Success : " __VA_ARGS__ L"\n"))
#define PRINT_INFO(...) (wprintf(L"[i] Info : " __VA_ARGS__ L"\n"))
#define PRINT_WARN(...) (wprintf(L"[!] Warning : " __VA_ARGS__ L"\n"))

#define	Add2Ptr(P, I)   ((PVOID)((PBYTE)(P) + (PBYTE)(I)))
#define Sub2Ptr(P, I)	((PVOID)((PBYTE)(P) - (PBYTE)(I)))

#define OSARCH_X64			L"x64"
#define OSARCH_X86			L"x86"
#define OSARCH_ARM			L"arm"
#define OSARCH_ARM64		L"arm64"
#define OSARCH_IA64			L"Intel Itanium-based"
#define OSARCH_UNKNOWN		L"Unknown"


// global variables
extern SC_HANDLE			g_KblasterService;
extern RTL_OSVERSIONINFOW	g_OsVersionInfo;
extern SYSTEM_INFO			g_SystemInfo;
extern const wchar_t*		g_Architecture;
extern const wchar_t*		g_KblastArchitecture;
extern HANDLE				g_KblasterDevice;
