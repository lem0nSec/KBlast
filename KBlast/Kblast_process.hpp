/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once

#include "globals.hpp"


typedef struct _EX_FAST_REF {
	union
	{
		VOID* Object;
		ULONGLONG RefCnt : 4;
		ULONGLONG Value;
	};
} EX_FAST_REF, * PEX_FAST_REF;

typedef struct _KBL_PROCESS_INFORMATION {
	PVOID eprocess;
	_EX_FAST_REF token;
	DWORD processId;
	DWORD ProtectionLevel;
	UNICODE_STRING ImageFileName;
	UNICODE_STRING Account;
	UNICODE_STRING ReferencedDomain;
} KBL_PROCESS_INFORMATION, * PKBL_PROCESS_INFORMATION;

BOOL Kblast_process_GetProcessIdByNameLazy(_In_ const wchar_t* ProcessName, _Inout_ PDWORD processId);
BOOL Kblast_process_GetActiveProcesses(_In_opt_ LPDWORD pProcessIds, _In_ DWORD dwLength, _Inout_ PDWORD pNumberOfProcessIds);
BOOL Kblast_process_AcquireProcessInformation(_In_ DWORD processId, _Inout_ PKBL_PROCESS_INFORMATION pProcessInformation, _In_ DWORD dwLength);
void Kblast_process_ReleaseProcessInformation(_In_ PKBL_PROCESS_INFORMATION pProcessInformation);
BOOL Kblast_process_GetDeviceDriverBaseAddress(_In_ const wchar_t* DeviceDriverName, _Inout_ LPVOID* BaseAddress);
DWORD Kblast_process_CheckTokenIntegrityLevel(_In_ HANDLE hProcess, _In_ DWORD dwRequestedIntegrity);
BOOL Kblast_process_SetTokenPrivilege(_In_ HANDLE hProcess, _In_ LPCWSTR Privilege, _In_ BOOL isEnable);
