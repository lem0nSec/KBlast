/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once

#include "globals.hpp"

typedef NTSTATUS(NTAPI* PRTLGETVERSION) (OUT PRTL_OSVERSIONINFOW lpVersionInformation);

BOOL Kblast_main_std_Help(int argc, wchar_t* input);
BOOL Kblast_main_std_Exit(int argc, wchar_t* input);
BOOL Kblast_main_std_ClearConsole(int argc, wchar_t* input);
BOOL Kblast_main_std_Pid(int argc, wchar_t* input);
BOOL Kblast_main_std_Time(int argc, wchar_t* input);
BOOL Kblast_main_std_Version(int argc, wchar_t* input);
BOOL Kblast_main_std_System(int argc, wchar_t* input);
