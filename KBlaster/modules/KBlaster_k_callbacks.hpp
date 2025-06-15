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
	ImageLoad,
	RegistryCallback,
	ObjectCallback,
	FilterCallback,
	NetworkCallback
} CallbackType;

typedef struct _KBLR_CALLBACK {
	CallbackType CallbackType;
} KBLR_CALLBACK, * PKBLR_CALLBACK;

#pragma pack(push, 1)
typedef struct _KBLR_CALLBACK_REMOVE {
	CallbackType CallbackType;
	ULONG_PTR RoutineIdentifier;
} KBLR_CALLBACK_REMOVE, * PKBLR_CALLBACK_REMOVE;
#pragma pack(pop)

typedef struct _ROUTINE_MODULE_INFORMATION {
	PVOID ModuleBase;
	ULONG ModuleImageSize;
	USHORT ModuleFileNameOffset;
	CHAR ModuleFullPathName[AUX_KLIB_MODULE_PATH_LEN];
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

typedef struct _CMREG_CALLBACK {
	LIST_ENTRY List;
	ULONG Unknown1;
	ULONG Unknown2;
	LARGE_INTEGER Cookie;
	PVOID Unknown3;
	PEX_CALLBACK_FUNCTION Function;
} CMREG_CALLBACK, * PCMREG_CALLBACK;













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

//PVOID KBlaster_k_GetCallbackStoragePointer(IN CALLBACK_TYPE cType);