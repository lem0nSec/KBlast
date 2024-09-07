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
#include "KBlast_c_utils.hpp" // utils are global as they may be requested by anything
#include "KBlast_c_privilege.hpp"
#include "../KBlaster/navigation.hpp"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Shlwapi.lib")

#pragma warning(disable: 4996)
#define UNICODE 1

#define KBLAST_CLT_TITLE	L"KBlast v1.1 ( by lem0nSec )"
#define KBLAST_CLT_VERSION	L"0.1"
#define KBLAST_DRV_BINARY	L"KBlaster.sys"
#define KBLAST_DRV_FILENAME	L"\\\\.\\KBlaster"
#define KBLAST_SRV_NAME		L"KBlaster"
#define KBLAST_VERSION		L"0.1"
#if defined(_M_X64)
#define KBLAST_ARCH			L"x64"
#elif defined(_M_IX86)
#define KBLAST_ARCH			L"x86"
#endif

#define OSARCH_X64			L"x64"
#define OSARCH_X86			L"x86"
#define OSARCH_ARM			L"arm"
#define OSARCH_ARM64		L"arm64"
#define OSARCH_IA64			L"Intel Itanium-based"
#define OSARCH_UNKNOWN		L"Unknown"

#if !defined(PRINT_FUNCTION_ERROR)
#define PRINT_FUNCTION_ERROR(...) (wprintf(L"IN_FUNCTION_ERROR " TEXT(__FUNCTION__) L" : " __VA_ARGS__))
#endif

#if !defined(PRINT_ERROR)
#define PRINT_ERROR(...) (wprintf(L"[-] ERROR : " __VA_ARGS__))
#endif

#if !defined(PRINT_SUCCESS)
#define PRINT_SUCCESS(...) (wprintf(L"[+] SUCCESS : " __VA_ARGS__))
#endif

#if !defined(PRINT_INFO)
#define PRINT_INFO(...) (wprintf(L"[i] INFO : " __VA_ARGS__))
#endif

#if !defined(PRINT_WARNING)
#define PRINT_WARNING(...) (wprintf(L"[!] WARNING : " __VA_ARGS__))
#endif


typedef struct _KBLAST_MEMORY_BUFFER {

	PVOID ptr;
	ULONG size;
	UCHAR buffer[250];

} KBLAST_MEMORY_BUFFER, * PKBLAST_MEMORY_BUFFER; // this should be written on another header file