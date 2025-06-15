/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <ntdef.h>
#include <wdm.h>
#include <aux_klib.h>

#include "..\offsets.hpp"

extern "C"

#define POOL_TAG		'Smel'
#define USER_POOL_TAG	'resU'

#define	Add2Ptr(P, I)   ((PVOID)((PUCHAR)(P) + (I)))
#define Sub2Ptr(P, I)	((PVOID)((PUCHAR)(P) - (I)))

#define ACQUIRE_READ_LOCK(lock) do {									\
			if (KeGetCurrentIrql() == PASSIVE_LEVEL && !lock) {			\
				KeEnterCriticalRegion();								\
				ExAcquirePushLockShared(&g_PushLock);					\
				lock = 1;												\
			}															\
		} while (0)
#define ACQUIRE_WRITE_LOCK(lock) do {									\
			if (KeGetCurrentIrql() == PASSIVE_LEVEL && !lock) {			\
				KeEnterCriticalRegion();								\
				ExAcquirePushLockExclusive(&g_PushLock);				\
				lock = 1;												\
			}															\
		} while (0)
#define RELEASE_READ_LOCK(lock) do {									\
			if (lock) {													\
				ExReleasePushLockShared(&g_PushLock);					\
				KeLeaveCriticalRegion();								\
				lock = 0;												\
			}															\
		} while (0)
#define RELEASE_WRITE_LOCK(lock) do {									\
			if (lock) {													\
				ExReleasePushLockExclusive(&g_PushLock);				\
				KeLeaveCriticalRegion();								\
				lock = 0;												\
			}															\
		} while (0)

typedef struct _KBLR_ASSIST_MODULE_EXTENDED_INFORMATION {
	ULONG NumberOfModules;
	PAUX_MODULE_EXTENDED_INFO AllModulesInformation;
} KBLR_ASSIST_MODULE_EXTENDED_INFORMATION, * PKBLR_ASSIST_MODULE_EXTENDED_INFORMATION;

extern EX_PUSH_LOCK		g_PushLock;
extern WindowsVersion	g_WindowsVersion;
extern BOOLEAN			g_Locked;