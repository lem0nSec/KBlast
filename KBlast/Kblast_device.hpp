/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once

#include "globals.hpp"
#include "../KBlaster/ioctl.hpp"


typedef enum _PROTECTION_OPTION {
	ProtectionWintcb,
	ProtectionLsa,
	ProtectionAntimalware,
	ProtectionNone
} PROTECTION_OPTION;

typedef struct _KBLR_TERM_REQUEST {
	ULONG processId;
} KBLR_TERM_REQUEST, * PKBLR_TERM_REQUEST;

typedef struct _KBLR_PROTECTION {
	ULONG processId;
	PROTECTION_OPTION Protection;
} KBLR_PROTECTION, * PKBLR_PROTECTION;

typedef struct _KBLR_TOKEN_PRIV {
	ULONG processId;
	BOOL IsEnable;
} KBLR_TOKEN_PRIV, * PKBLR_TOKEN_PRIV;

typedef struct _KLBR_TOKEN {
	ULONG processId;
	ULONG targetProcessId;
	BOOL IsSteal;
} KLBR_TOKEN, * PKLBR_TOKEN;

typedef enum {
	ProcessNotify,
	ThreadNotify,
	ImageLoad,
	RegistryCallback,
	ObjectCallback,
	FilterCallback,
	NetworkCallout
} CallbackType;

#pragma pack(push, 1)
typedef struct _KBLR_CALLBACK {
	CallbackType CallbackType;
	ULONG_PTR hRoutine;
} KBLR_CALLBACK, * PKBLR_CALLBACK;
#pragma pack(pop)

typedef struct _ROUTINE_MODULE_INFORMATION {
	PVOID ModuleBase;
	ULONG ModuleImageSize;
	USHORT ModuleFileNameOffset;
	CHAR ModuleFullPathName[256]; // AUX_KLIB_MODULE_PATH_LEN
} ROUTINE_MODULE_INFORMATION, * PROUTINE_MODULE_INFORMATION;

typedef struct _ROUTINE_INFORMATION {
	ULONG_PTR Handle;
	PVOID PointerToHandle;
	PVOID Routine;
	ROUTINE_MODULE_INFORMATION ModuleInformation;
} ROUTINE_INFORMATION, * PROUTINE_INFORMATION;

typedef struct _KBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION {
	PVOID pArray;
	ULONG NumberOfRoutines;
	ROUTINE_INFORMATION RoutineInformation[ANYSIZE_ARRAY];
} KBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION, * PKBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION;

typedef enum _LOCK_OPERATION {
	IoReadAccess,
	IoWriteAccess,
	IoModifyAccess
} LOCK_OPERATION;

typedef struct _KBLR_MEMORY_BUFFER {
	PVOID ptr;
	ULONG size;
	LOCK_OPERATION Operation;
	CHAR buffer[250];
} KBLR_MEMORY_BUFFER, * PKBLR_MEMORY_BUFFER;

BOOL Kblast_device_IoctlProcess(int argc, wchar_t* input);
BOOL Kblast_device_IoctlProtection(int argc, wchar_t* input);
BOOL Kblast_device_IoctlToken(int argc, wchar_t* input);
BOOL Kblast_device_IoctlCallback(int argc, wchar_t* input);
BOOL Kblast_device_IoctlMisc(int argc, wchar_t* input);
