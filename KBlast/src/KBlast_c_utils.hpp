#pragma once

#include "globals.hpp"


typedef struct _KBLAST_COMMANDLINE_ARGUMENTS {

	LPCSTR arg1;
	LPCSTR arg2;
	LPCSTR arg3;

} KBLAST_COMMANDLINE_ARGUMENTS, * PKBLAST_COMMANDLINE_ARGUMENTS;


char* KBlast_c_utils_UnicodeStringToAnsiString(IN wchar_t* input);
void KBlast_c_utils_FreeAnsiString(IN char* ansiString);
int KBlast_c_utils_GetCommandLineArguments(IN char* inBuffer, IN BYTE separator, OUT PKBLAST_COMMANDLINE_ARGUMENTS args);
char* KBlast_c_utils_GetImageNameByFullPath(char* FullImagePath);