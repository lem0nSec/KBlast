/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once

#include "globals.hpp"

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId; // pid of the process which holds the handle
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _OBJECT_BASIC_INFORMATION {
    ULONG                   Attributes;
    ACCESS_MASK             DesiredAccess;
    ULONG                   HandleCount;
    ULONG                   ReferenceCount;
    ULONG                   PagedPoolUsage;
    ULONG                   NonPagedPoolUsage;
    ULONG                   Reserved[3];
    ULONG                   NameInformationLength;
    ULONG                   TypeInformationLength;
    ULONG                   SecurityDescriptorLength;
    LARGE_INTEGER           CreationTime;
} OBJECT_BASIC_INFORMATION, * POBJECT_BASIC_INFORMATION;

#pragma warning (disable: 4200)
typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING          Name;
    WCHAR                   NameBuffer[0];
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef struct _IPC_SET_FUNCTION_RETURN_DEEP_PARAMETER {
    UINT64 rip;         
    UINT64 rcx;
} IPC_SET_FUNCTION_RETURN_DEEP_PARAMETER, * PIPC_SET_FUNCTION_RETURN_DEEP_PARAMETER;

typedef struct _IPC_SET_FUNCTION_RETURN_PARAMETER {
    PIPC_SET_FUNCTION_RETURN_DEEP_PARAMETER pInternalStruct;
    ULONG rdx;
    ULONG unk;
} IPC_SET_FUNCTION_RETURN_PARAMETER, * PIPC_SET_FUNCTION_RETURN_PARAMETER;

typedef struct _REPLACEABLE_POINTER {
    const wchar_t* Module;
    const char* Name;
    PVOID FakePtr;
    PVOID RealPtr;
} REPLACEABLE_POINTER, * PREPLACEABLE_POINTER;

typedef VOID(NTAPI* PRTLINITUNICODESTRING)(_Inout_ PUNICODE_STRING DestinationString, _In_opt_ PCWSTR SourceString);
typedef NTSTATUS(NTAPI* PNTOPENFILE)(_Out_ HANDLE FileHandle, _In_ ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ ULONG ShareAccess, _In_ ULONG OpenOptions);
typedef NTSTATUS(NTAPI* PNTQUERYSYSTEMINFORMATION)(_In_ int SystemInformationClass, _Inout_ PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength);
typedef NTSTATUS(NTAPI* PNTQUERYOBJECT)(_In_opt_ HANDLE Handle, _In_ int ObjectInfoClass, _Out_opt_ PVOID ObjectInformation, _In_ ULONG ObjectInformationLength, _Out_opt_ PULONG ReturnLength);
typedef BOOL(WINAPI* PDEVICEIOCONTROL)(_In_ HANDLE hDevice, _In_ DWORD dwIoControlCode, _In_opt_ LPVOID lpInBuffer, _In_ DWORD nInBufferSize, _Out_opt_ LPVOID lpOutBuffer, _In_ DWORD nOutBufferSize, _Out_opt_ LPDWORD lpBytesReturned, _Inout_opt_ LPOVERLAPPED lpOverlapped);
typedef HLOCAL(WINAPI* PLOCALALLOC) (__in UINT uFlags, __in SIZE_T uBytes);
typedef HLOCAL(WINAPI* PLOCALFREE) (__deref HLOCAL hMem);
typedef int(NTAPI* PWCSCMP)(const wchar_t* string1, const wchar_t* string2);

BOOL KBlast_c_ci_GetCiOptionsOffset(PULONG G_CIoptionsOffset);
BOOL KBlast_c_ci_KexecDD();