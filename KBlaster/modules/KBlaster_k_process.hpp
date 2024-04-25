/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/

#pragma once

#include "../globals.hpp"
#include "KBlaster_k_protection.hpp"

typedef struct _KBLASTER_PROCESS_INFORMATION
{
	PVOID Eprocess;
	PVOID Token;
	ULONG64 UniqueProcessId;
	UCHAR ImageFileName[16];
	PROCESS_PROTECTION_INFO ProtectionInformation;
} KBLASTER_PROCESS_INFORMATION, * PKBLASTER_PROCESS_INFORMATION;

typedef struct _KBLASTER_FULL_PROCESS_INFORMATION {
	ULONG64 ProcNumber;
	union {
		PKBLASTER_PROCESS_INFORMATION pProcInformation;
	};
} KBLASTER_FULL_PROCESS_INFORMATION, * PKBLASTER_FULL_PROCESS_INFORMATION;