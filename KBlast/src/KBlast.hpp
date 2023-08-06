#pragma once

#include "globals.hpp"
#include "KBlast_c_service.hpp"
#include "KBlast_c_privilege.hpp"
#include "driver/KBlast_c_device_dispatch.hpp"






wchar_t KBlast_c_banner[] =
L"    __ __ ____  __           __\n"
L"   / //_// __ )/ /___ ______/ /_\t| Author: Angelo Frasca Caccia ( lem0nSec_ )\n"
L"  / ,<  / __  / / __ `/ ___/ __/\t| Title: KBlast\n"
L" / /| |/ /_/ / / /_/ (__  ) /_\t\t| Version: v1.0\n"
L"/_/ |_/_____/_/\\__,_/____/\\__/\t\t| Website: http://www.github.com/lem0nSec/KBlast\n"
L"------------------------------------------------------->>>\n";


wchar_t KBlast_c_banner_test[] =
L"-------------------------------------------\n"
L"    __ __ ____  __           __\n"
L"   / //_// __ )/ /___ ______/ /_\n"
L"  / ,<  / __  / / __ `/ ___/ __/\n"
L" / /| |/ /_/ / / /_/ (__  ) /_\n"
L"/_/ |_/_____/_/\\__,_/____/\\__/\n"
L" ------------------------------------------\n"
L"| Author: Angelo Frasca Caccia ( lem0nSec_ )\n"
L"| Application: KBlast.exe\n"
L"| Version: v1.0\n"
L"| Website: https://www.github.com/lem0nSec/KBlast\n"
L" ------------------------------------------\n";


/*
typedef struct _KBLAST_BUFFER {

	int integer1;
	int integer2;
	char* string1;
	char* string2;

} KBLAST_BUFFER, * PKBLAST_BUFFER;
*/

// Driver upper commands

#define KBLAST_MOD_GENERIC		L"misc|"
#define KBLAST_MOD_PROTECTION	L"prot|"
#define KBLAST_MOD_PRIVILEGES	L"priv|"
#define KBLAST_MOD_TOKEN		L"tokn|"
#define KBLAST_MOD_CALLBACK		L"call|"