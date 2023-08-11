/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once

#include <Windows.h>
#include <winternl.h>
#include <wincrypt.h>
#include <stdio.h>
#include "KBlast_c_utils.hpp" // utils are global as they may be requested by anything

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "crypt32.lib")

#pragma warning(disable: 4996)
#define UNICODE 1

#define KBLAST_CLT_TITLE	L"KBlast v1.0 ( by lem0nSec )"
#define KBLAST_CLT_VERSION	L"1.0"
#define KBLAST_DRV_BINARY	L"KBlaster.sys"
#define KBLAST_DRV_FILENAME	L"\\\\.\\KBlaster"
#define KBLAST_SRV_NAME		L"KBlaster"
#define KBLAST_VERSION		L"1.0"




typedef struct _KBLAST_MEMORY_BUFFER {

	PVOID ptr;
	ULONG size;
	UCHAR buffer[250];

} KBLAST_MEMORY_BUFFER, * PKBLAST_MEMORY_BUFFER; // this should be written on another header file


typedef struct _KBLAST_HELP_MENU {

	const wchar_t* Command;
	const wchar_t* Description;

} KBLAST_HELP_MENU, * PKBLAST_HELP_MENU;