/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once

#include "globals.hpp"

#define KBL_COMM_ELEMS(A) (sizeof(A) / sizeof(KBL_COMMAND))

typedef struct _KBL_COMMANDLINE_ARGS {
	LPCSTR Action;
	LPCSTR Type;
	LPCSTR blob;
	LPCSTR name;
	DWORD container;
	SIZE_T size;
	ULONG ProcessId;
	ULONG TargetProcessId;
	PVOID Value;
} KBL_COMMANDLINE_ARGS, * PKBL_COMMANDLINE_ARGS;

typedef struct _KBL_MODULE_COMMANDLINE {
	DWORD NumberOfArguments;
	KBL_COMMANDLINE_ARGS Commandline;
} KBL_MODULE_COMMANDLINE, * PKBL_MODULE_COMMANDLINE;

typedef BOOL(*KBL_F_BOOL) (int argc, wchar_t* input);

typedef struct _KBL_COMMAND {
	LPCWSTR lpCommand;
	LPCWSTR lpDescription;
	KBL_F_BOOL Function;
} KBL_COMMAND, * PKBL_COMMAND;


BOOL Kblast_string_CreateAnsiStringFromUnicodeString(_In_ PUNICODE_STRING pUnicodeString, _Out_ PANSI_STRING pAnsiString);
void Kblast_string_FreeAnsiString(_In_ PANSI_STRING pAnsiString);
BOOL Kblast_string_ParseCommandline(_In_ wchar_t* Commandline, _Inout_ PKBL_MODULE_COMMANDLINE pArguments);
BOOL Kblast_string_CommandSearch(_In_ LPCWSTR Input, _In_ PKBL_COMMAND pArray, _In_ SIZE_T szArray, _Inout_ PDWORD Index);
PVOID Kblast_string_StringToPointer(_In_ LPCSTR StringPointer);
char* Kblast_string_GetImageNameByFullPath(_In_ char* FullImagePath);
void Kblast_string_AdjustInputCommandString(_In_ LPCWSTR InputCommandString);
BOOL Kblast_string_ConvertStringToHexBlob(_In_ LPCSTR StringBlob, _Inout_ LPVOID Blob, _Inout_ PDWORD ReturnLength);
void Kblast_string_HexDump(_In_ const void* data, _In_ SIZE_T size);
