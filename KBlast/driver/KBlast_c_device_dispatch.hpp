/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once

#include "../globals.hpp"
#include "../ioctl.hpp"
#include "../KBlast_c_blob.hpp"


typedef struct _KBLAST_BUFFER {

	int integer1;
	int integer2;
	char* string1;
	char* string2;

} KBLAST_BUFFER, * PKBLAST_BUFFER;


typedef struct _CALLBACK_MODULE_INFORMATION {

	PVOID ModuleBase;
	ULONG ModuleImageSize;
	USHORT ModuleFileNameOffset;
	CHAR ModuleFullPathName[256];

} CALLBACK_MODULE_INFORMATION, * PCALLBACK_MODULE_INFORMATION;


typedef struct _CALLBACK_INFORMATION {

	ULONG64 CallbackHandle;
	PVOID PointerToHandle;
	PVOID CallbackFunctionPointer;
	CALLBACK_MODULE_INFORMATION ModuleInformation;

} CALLBACK_INFORMATION, * PCALLBACK_INFORMATION;


typedef struct _PROCESS_KERNEL_CALLBACK_STORAGE {

	PVOID Array;
	ULONG CallbackQuota;
	CALLBACK_INFORMATION CallbackInformation[50];

} PROCESS_KERNEL_CALLBACK_STORAGE, * PPROCESS_KERNEL_CALLBACK_STORAGE;

typedef enum _HELP_MODULE {

	MISC,
	PROTECTION,
	TOKEN,
	CALLBACKS

} HELP_MENU;


BOOL KBlast_c_device_dispatch_misc(wchar_t* input);
BOOL KBlast_c_device_dispatch_protection(wchar_t* input);
BOOL KBlast_c_device_dispatch_token(wchar_t* input);
BOOL KBlast_c_device_dispatch_privileges(wchar_t* input);
BOOL KBlast_c_device_dispatch_callbacks(wchar_t* input);