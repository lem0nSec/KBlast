/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once


#include "../globals.hpp"

typedef struct _KBLR_MEMORY_BUFFER {
	PVOID ptr;
	ULONG size;
	LOCK_OPERATION Operation;
	CHAR buffer[250];
} KBLR_MEMORY_BUFFER, *PKBLR_MEMORY_BUFFER;
