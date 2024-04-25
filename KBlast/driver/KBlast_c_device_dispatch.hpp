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
	PVOID pointer;
	ULONG64 uPointer;
	ULONG uGeneric;
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

typedef struct _PS_PROTECTION
{
	UCHAR Type : 3;
	UCHAR Audit : 1;    // Reserved
	UCHAR Signer : 4;

} PS_PROTECTION, * PPS_PROTECTION;

typedef struct _PROCESS_PROTECTION_INFO
{
	UCHAR SignatureLevel;
	UCHAR SectionSignatureLevel;
	PS_PROTECTION Protection;

} PROCESS_PROTECTION_INFO, * PPROCESS_PROTECTION_INFO;

typedef struct _KBLAST_PROCESS_INFORMATION {

	PVOID Eprocess;
	PVOID Token;
	ULONG64 UniqueProcessId;
	UCHAR ImageFileName[16];
	PROCESS_PROTECTION_INFO ProtectionInformation;

} KBLAST_PROCESS_INFORMATION, * PKBLAST_PROCESS_INFORMATION;

typedef struct _KBLAST_FULL_PROCESS_INFORMATION {
	ULONG64 ProcNumber;
	union {
		PKBLAST_PROCESS_INFORMATION pProcInformation;
	};
} KBLAST_FULL_PROCESS_INFORMATION, * PKBLAST_FULL_PROCESS_INFORMATION;

typedef enum _HELP_MODULE {

	GENERIC,
	MISC,
	BLOBS,
	PROTECTION,
	TOKEN,
	CALLBACKS,
	PROCESS

} HELP_MENU;


typedef struct _KBLAST_HELP_MENU {

	const wchar_t* Command;
	const wchar_t* Description;

} KBLAST_HELP_MENU, * PKBLAST_HELP_MENU;


void KBlast_c_module_help(HELP_MENU help);
BOOL KBlast_c_device_dispatch_misc(wchar_t* input);
BOOL KBlast_c_device_dispatch_blob(wchar_t* input);
BOOL KBlast_c_device_dispatch_protection(wchar_t* input);
BOOL KBlast_c_device_dispatch_token(wchar_t* input);
BOOL KBlast_c_device_dispatch_callbacks(wchar_t* input);
BOOL KBlaster_c_device_dispatch_process(wchar_t* input);