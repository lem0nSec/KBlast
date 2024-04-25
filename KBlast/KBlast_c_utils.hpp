/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once

#include "globals.hpp"

typedef struct _KBLAST_COMMANDLINE_ARGUMENTS {

	LPCSTR action;
	LPCSTR type;
	LPCSTR blob;
	LPCSTR name;
	DWORD container;
	SIZE_T size;
	ULONG pid;
	ULONG targetpid;
	PVOID pointer;

} KBLAST_COMMANDLINE_ARGUMENTS, *PKBLAST_COMMANDLINE_ARGUMENTS;

typedef struct _KBLAST_USER_PROCESS_INFORMATION {

	DWORD processID;
	wchar_t ImageFileName[MAX_PATH];
	wchar_t TokenOwner[MAX_PATH];

} KBLAST_USER_PROCESS_INFORMATION, * PKBLAST_USER_PROCESS_INFORMATION;


char* KBlast_c_utils_UnicodeStringToAnsiString(IN wchar_t* input);
void KBlast_c_utils_FreeAnsiString(IN char* ansiString);
char* KBlast_c_utils_GetImageNameByFullPath(char* FullImagePath);
int KBlast_c_utils_GetCommandlineArguments(IN char* inBuffer, OUT PKBLAST_COMMANDLINE_ARGUMENTS pArgs);
PVOID KBlast_c_utils_StringToKernelPointer(LPCSTR strPointer, DWORD szPtr);
BOOL KBlast_c_utils_ListProcessInformation(PKBLAST_USER_PROCESS_INFORMATION procInfo);