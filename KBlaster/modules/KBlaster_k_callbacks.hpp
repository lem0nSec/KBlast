/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once


#include "../globals.hpp"

#define INVERT_ROUTINE_HANDLE(H)	*(PVOID*)(H & 0xfffffffffffffff8)

typedef enum {
	ProcessNotify,
	ThreadNotify,
	ImageNotify,
	RegistryCallback,
	ObjectCallbacks,
	FilterCallback,
	NetworkCallback
} CallbackType;

typedef enum {
	ProcessType,
	ThreadType,
	DesktopType
} ObjectCallbackType;

typedef struct _KBLR_CALLBACK_OPERATION {
	CallbackType CallbackType;
	union {
		ULONG_PTR RoutineIdentifier;
	} NotifyRoutine;
	union {
		LARGE_INTEGER Cookie;
	} RegistryCallback;
	union {
		PVOID CallbackEntry;
	} ObjectCallback;
} KBLR_CALLBACK_OPERATION, * PKBLR_CALLBACK_OPERATION;

typedef struct _ROUTINE_MODULE_INFORMATION {
	PVOID ModuleBase;
	ULONG ModuleImageSize;
	USHORT ModuleFileNameOffset;
	CHAR ModuleFullPathName[AUX_KLIB_MODULE_PATH_LEN];
} ROUTINE_MODULE_INFORMATION, * PROUTINE_MODULE_INFORMATION;

typedef struct _NOTIFY_ROUTINE {
	ULONG_PTR Handle;
	PVOID PointerToHandle;
	PVOID Routine;
} NOTIFY_ROUTINE, * PNOTIFY_ROUTINE;

typedef struct _REGISTRY_CALLBACK {
	LARGE_INTEGER Cookie;
	PVOID Routine;
} REGISTRY_CALLBACK, * PREGISTRY_CALLBACK;

typedef struct _OBJECT_CALLBACK {
	PVOID CallbackEntry;
	ObjectCallbackType Type;
	OB_OPERATION Operation;
	BOOL Enabled;
	PVOID PreOperation;
	PVOID PostOperation;
} OBJECT_CALLBACK, * POBJECT_CALLBACK;

typedef struct _ROUTINE_INFORMATION {
	ROUTINE_MODULE_INFORMATION FirstModuleInformation;
	ROUTINE_MODULE_INFORMATION SecondModuleInformation;
	union {
		NOTIFY_ROUTINE NotifyRoutine;
		REGISTRY_CALLBACK RegistryCallback;
		OBJECT_CALLBACK ObjectCallback;
	} SpecificRoutineInformation;
} ROUTINE_INFORMATION, * PROUTINE_INFORMATION;

typedef struct _KBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION {
	PVOID pArray;
	ULONG NumberOfRoutines;
	ROUTINE_INFORMATION RoutineInformation[ANYSIZE_ARRAY];
} KBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION, * PKBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION;

typedef struct _CMREG_CALLBACK {
	LIST_ENTRY List;
	ULONG Unknown1;
	ULONG Unknown2;
	LARGE_INTEGER Cookie;
	PVOID Unknown3;
	PEX_CALLBACK_FUNCTION Function;
} CMREG_CALLBACK, * PCMREG_CALLBACK;

// 0xd8 bytes (sizeof) - Win10 22h2 (build 19045) to Win11 23h2
// This struct can be used in Win11 24h2 as long as the members past
// CallbackList are not used. 24h2 has two more members past CallbasList,
// namely ...
typedef struct _OBJECT_TYPE_23H2 {
	LIST_ENTRY TypeList;
	UNICODE_STRING Name;
	VOID* DefaultObject;
	UCHAR Index;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	UCHAR TypeInfo_gap[0x78]; /* struct _OBJECT_TYPE_INITIALIZER */
	EX_PUSH_LOCK TypeLock;
	ULONG Key;
	LIST_ENTRY CallbackList;
} OBJECT_TYPE_23H2, * POBJECT_TYPE_23H2;

typedef struct _OB_CALLBACK_ENTRY {
	LIST_ENTRY CallbackList;
	OB_OPERATION Operations;
	BOOL Enabled;
	struct OB_CALLBACK* Entry;
	POBJECT_TYPE ObjectType;
	POB_PRE_OPERATION_CALLBACK PreOperation;
	POB_POST_OPERATION_CALLBACK PostOperation;
	KSPIN_LOCK Lock;
} OB_CALLBACK_ENTRY, * POB_CALLBACK_ENTRY;












/*
typedef struct _OBJECT_TYPE {
	LIST_ENTRY TypeList;
	UNICODE_STRING Name;
	PVOID DefaultObject;
	UCHAR Index;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	unsigned char TypeInfo[0x78]; // OBJECT_TYPE_INITIALIZER TypeInfo;
	EX_PUSH_LOCK TypeLock;
	ULONG Key;
	LIST_ENTRY CallbackList; //offset 0xC8
} OBJECT_TYPE, * POBJECT_TYPE;

typedef struct _CALLBACK_ENTRY
{
	INT16 Version;
	unsigned char unknown[6];
	POB_OPERATION_REGISTRATION RegistrationContext;
	UNICODE_STRING Altitude;
} CALLBACK_ENTRY, * PCALLBACK_ENTRY;


typedef struct _CALLBACK_ENTRY_ITEM {
	LIST_ENTRY EntryItemList;
	OB_OPERATION Operations;
	OB_OPERATION Active; // DWORD Active
	PCALLBACK_ENTRY CallbackEntry;
	POBJECT_TYPE ObjectType;
	POB_PRE_OPERATION_CALLBACK PreOperation; //offset 0x28
	POB_POST_OPERATION_CALLBACK PostOperation; //offset 0x30
	__int64 unk;
} CALLBACK_ENTRY_ITEM, * PCALLBACK_ENTRY_ITEM;
*/