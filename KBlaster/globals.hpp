/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once

#include "modules/KBlaster_k_assist.hpp"

typedef int BOOL;
extern NTSTATUS Kblaster_assist_Initialize();
extern NTSTATUS Kblaster_assist_GetLoadedModulesFillBuffer(_Inout_ PKBLR_ASSIST_MODULE_EXTENDED_INFORMATION pAllModules);
extern void Kblaster_assist_GetLoadedModulesFreeBuffer(_In_ PKBLR_ASSIST_MODULE_EXTENDED_INFORMATION pAllModules);