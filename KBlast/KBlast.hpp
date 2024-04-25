/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once

#include "globals.hpp"
#include "KBlast_c_service.hpp"
#include "KBlast_c_privilege.hpp"
#include "driver/KBlast_c_device_dispatch.hpp"

typedef NTSTATUS(NTAPI* PRTLGETVERSION) (OUT PRTL_OSVERSIONINFOW lpVersionInformation);

// Driver upper commands

#define KBLAST_MOD_MISC			L"misc"
#define KBLAST_MOD_BLOB			L"blob"
#define KBLAST_MOD_PROTECTION	L"protection"
#define KBLAST_MOD_TOKEN		L"token"
#define KBLAST_MOD_CALLBACK		L"callback"
#define KBLAST_MOD_PROCESS		L"process"