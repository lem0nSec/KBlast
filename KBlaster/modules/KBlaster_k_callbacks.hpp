/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once


#include "../globals.hpp"


typedef enum _CALLBACK_TYPE {

	ARRAY_PROCESS,
	ARRAY_THREAD,
	ARRAY_IMAGE,
	LISTENTRY_REGISTRY,
	LISTENTRY_OBJECT

} CALLBACK_TYPE;


typedef struct _CALLBACK_MODULE_INFORMATION {

	PVOID ModuleBase;
	ULONG ModuleImageSize;
	USHORT ModuleFileNameOffset;
	CHAR ModuleFullPathName[AUX_KLIB_MODULE_PATH_LEN];

} CALLBACK_MODULE_INFORMATION, * PCALLBACK_MODULE_INFORMATION;


typedef struct _CALLBACK_INFORMATION {

	ULONG64 CallbackHandle;
	PVOID PointerToHandle;
	PVOID CallbackFunctionPointer;
	CALLBACK_MODULE_INFORMATION ModuleInformation;

} CALLBACK_INFORMATION, * PCALLBACK_INFORMATION;


typedef struct _PROCESS_KERNEL_CALLBACK_STORAGE {

	PVOID Storage;
	ULONG CallbackQuota;
	CALLBACK_INFORMATION CallbackInformation[50];

} PROCESS_KERNEL_CALLBACK_STORAGE, * PPROCESS_KERNEL_CALLBACK_STORAGE;


typedef struct _CMREG_CALLBACK {
	
	LIST_ENTRY List;
	ULONG Unknown1;
	ULONG Unknown2;
	LARGE_INTEGER Cookie;
	PVOID Unknown3;
	PEX_CALLBACK_FUNCTION Function;

} CMREG_CALLBACK, * PCMREG_CALLBACK;

PVOID KBlaster_k_GetCallbackStoragePointer(IN CALLBACK_TYPE cType);