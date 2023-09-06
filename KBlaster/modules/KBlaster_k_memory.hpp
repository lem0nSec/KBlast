/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once


#include "../globals.hpp"


typedef enum _KBLAST_MEMORY_ACTION {

	MEMORY_WRITE,
	MEMORY_READ

} KBLAST_MEMORY_ACTION;


typedef struct _KBLAST_MEMORY_BUFFER {

	PVOID ptr;
	ULONG size;
	CHAR buffer[250];

} KBLAST_MEMORY_BUFFER, *PKBLAST_MEMORY_BUFFER;


NTSTATUS KBlaser_k_memory_manage(IN PKBLAST_MEMORY_BUFFER InBuf, OUT OPTIONAL PVOID OutBuf, KBLAST_MEMORY_ACTION action);
NTSTATUS KBlaster_k_memory_dse(IN ULONG offset, OUT PVOID pOutBuf);