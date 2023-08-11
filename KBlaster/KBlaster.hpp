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


typedef struct _KBLAST_BUFFER {

	int integer1;
	int integer2;
	char* string1;
	char* string2;

} KBLAST_BUFFER, * PKBLAST_BUFFER;


extern "C"

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT pDriverObject, _In_ PUNICODE_STRING pRegistryPath);
NTSTATUS KBlaster_k_ProcessProtection(int processID, PROTECTION_OPTION prOption);
NTSTATUS KBlaster_k_TokenPrivilegeManipulate(int processID, PRIVILEGES_ACTION prOption);
NTSTATUS KBlaster_k_TokenContextSteal(int processID, int targetProcessID);
NTSTATUS KBlaster_k_TokenContextRestore(int processID);
NTSTATUS KBlaster_k_EnumProcessCallbacks(IN ULONG szAvailable, IN CALLBACK_TYPE cType, OUT PVOID pOutBuf);




/*
* TODO:
*
* 1) Enumerate modules (.sys)
* 2) Enumerate userland processes (provide information that are inaccessible from userland to make the whole thing more skechy)
* 3) Hide userland processes
* 4) Enumerate DSE + enable the client to edit it
* 5) Remove callbacks
* 6) Patch/Neutralize callbacks (xor rax,rax - ret)
* 7) Inject kernel shellcode inside callbacks
*/















/*
DRIVER_INITIALIZE		DriverEntry;
DRIVER_UNLOAD			DriverCleanup;
DRIVER_DISPATCH			UnSupport;
__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)				DRIVER_DISPATCH KBlast_IOCTLDispatchar;
*/


/*
typedef struct _INTEGRITY_LEVEL {

	DWORD32 IntegrityLevelIndex;
	DWORD32 MandatoryPolicy;

} INTEGRITY_LEVEL, * PINTEGRITY_LEVEL;


typedef struct _SE_AUDIT_PROCESS_CREATION_INFO {

	POBJECT_NAME_INFORMATION ImageFileName;

} SE_AUDIT_PROCESS_CREATION_INFO, * PSE_AUDIT_PROCESS_CREATION_INFO;
*/