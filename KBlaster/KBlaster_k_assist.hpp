#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <ntdef.h>
#include <wdm.h>
#include <aux_klib.h>

#include "..\offsets.hpp"

#define POOL_TAG		'Smel'
#define USER_POOL_TAG	'resU'

#define	Add2Ptr(P, I)   ((PVOID)((PUCHAR)(P) + (I)))
#define Sub2Ptr(P, I)	((PVOID)((PUCHAR)(P) - (I)))

#define CHECK_STATUS(status) if (!NT_SUCCESS(status)) { goto Exit; }
#define CHECK_VALUE(value, status_in, status_out) if (!value) { status_in = status_out; goto Exit; }

typedef struct _KBLR_ASSIST_MODULE_EXTENDED_INFORMATION {
	ULONG NumberOfModules;
	PAUX_MODULE_EXTENDED_INFO AllModulesInformation;
} KBLR_ASSIST_MODULE_EXTENDED_INFORMATION,
* PKBLR_ASSIST_MODULE_EXTENDED_INFORMATION;

extern ULONG_PTR g_PushLock;
extern WindowsVersion g_WindowsVersion;
