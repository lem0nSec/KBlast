#pragma once

#include <Windows.h>
#include <winternl.h>
#include <wincrypt.h>
#include <stdio.h>
#include "KBlast_c_utils.hpp" // utils are global as they may be requested by anything

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "crypt32.lib")

#define UNICODE 1

#define KBLAST_CLT_TITLE	L"KBlast v1.0 ( by lem0nSec )"
#define KBLAST_CLT_VERSION	L"1.0"
#define KBLAST_DRV_BINARY	L"KBlaster.sys"
#define KBLAST_DRV_FILENAME	L"\\\\.\\KBlaster"
#define KBLAST_SRV_NAME		L"KBlaster"