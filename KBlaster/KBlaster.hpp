/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once

#include "globals.hpp"
#include "ioctl.hpp"
#include "modules/KBlaster_k_token.hpp"
#include "modules/KBlaster_k_protection.hpp"
#include "modules/KBlaster_k_callbacks.hpp"
#include "modules/KBlaster_k_memory.hpp"
#include "modules/KBlaster_k_process.hpp"


extern "C"

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT pDriverObject, _In_ PUNICODE_STRING pRegistryPath);
NTSTATUS KBlaster_k_ProcessProtection(int processID, PROTECTION_OPTION prOption);
NTSTATUS KBlaster_k_TokenPrivilegeManipulate(int processID, PRIVILEGES_ACTION prOption);
NTSTATUS KBlaster_k_TokenContextSteal(int processID, int targetProcessID);
NTSTATUS KBlaster_k_TokenContextRestore(int processID);
NTSTATUS KBlaster_k_EnumProcessCallbacks(IN ULONG szAvailable, IN CALLBACK_TYPE cType, OUT PVOID pOutBuf);
NTSTATUS KBlaster_k_RemoveCallbackRoutine(IN PVOID pObject, IN CALLBACK_TYPE cType);
NTSTATUS KBlaster_k_ProcessList(OUT PVOID pProcInfo);
NTSTATUS KBlaster_k_ProcessTerminate(IN ULONG processID);
//NTSTATUS KBlaster_k_ProcessUnlink(IN ULONG UniqueProcessId);