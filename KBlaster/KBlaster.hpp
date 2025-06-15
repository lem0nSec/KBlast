/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once

#include "globals.hpp"
#include "ioctl.hpp"

extern "C"

// all function definitions
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT pDriverObject, _In_ PUNICODE_STRING pRegistryPath);
NTSTATUS Kblaster_ppl_SetProtection( _In_ PVOID pProtectionRequest, _In_ ULONG RequestLength );
NTSTATUS Kblaster_token_SetPrivileges( _In_ PVOID pTokenPrivRequest, _In_ ULONG RequestLength );
NTSTATUS Kblaster_token_SetContext( _In_ PVOID pTokenRequest, _In_ ULONG RequestLength );
NTSTATUS Kblaster_process_TerminateProcess( _In_ PVOID pTerminationRequest, _In_ ULONG RequestLength );
NTSTATUS Kblaster_memory_CopyMemory(_Inout_ PVOID pMemoryRequest, _In_ ULONG RequestLength);
NTSTATUS Kblaster_callback_EnumerateRoutines(_Inout_ PVOID SystemBuffer, _In_ ULONG InputBufferLength, _In_ ULONG OutputBufferLength);
NTSTATUS Kblaster_callback_RemoveRoutine(_Inout_ PVOID SystemBuffer, _In_ ULONG InputBufferLength);
