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

/*
typedef struct _KBLAST_BUFFER {

	int integer1;
	int integer2;
	char* string1;
	char* string2;

} KBLAST_BUFFER, * PKBLAST_BUFFER;
*/

// Driver upper commands

#define KBLAST_MOD_MISC			L"misc|"
#define KBLAST_MOD_PROTECTION	L"prot|"
#define KBLAST_MOD_PRIVILEGES	L"priv|"
#define KBLAST_MOD_TOKEN		L"tokn|"
#define KBLAST_MOD_CALLBACK		L"call|"


KBLAST_HELP_MENU Generic_Cmds[7] = {
	{L"help", L"Show this help"},
	{L"quit", L"Quit KBlast"},
	{L"cls", L"Clear the screen"},
	{L"banner", L"Print KBlast banner"},
	{L"pid", L"Show current pid"},
	{L"time", L"Display system time"},
	{L"!{cmd}", L"Execute system command"}
};



//KBLAST_HELP_MENU help_gen = { 0 };

//L"This is the help menù for the generic KBlast module.\nThere's no need to prepend the module name to use these commands.\nCommands in this section do not open kernel interactions.\n";