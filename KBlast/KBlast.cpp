/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlast.hpp"


RTL_OSVERSIONINFOW OSinfo = { 0 };
SYSTEM_INFO OSinfo2 = { 0 };

void KBlast_c_GetInfo(DWORD dwOption)
{
	SYSTEMTIME sTime = { 0 };
	DWORD dwBuild = 0;
	HMODULE ntdll = 0;
	PRTLGETVERSION RtlGetVersion = 0;
	const wchar_t* kArch = 0;

	if (OSinfo.dwOSVersionInfoSize == 0)
	{
		OSinfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
		ntdll = GetModuleHandleW(L"ntdll.dll");
		if (ntdll != 0)
		{
			RtlGetVersion = (PRTLGETVERSION)GetProcAddress(ntdll, "RtlGetVersion");
			if (RtlGetVersion != 0)
			{
				RtlGetVersion(&OSinfo);
			}
		}
	}

	GetSystemInfo(&OSinfo2);

	switch (OSinfo2.wProcessorArchitecture)
	{
	case PROCESSOR_ARCHITECTURE_AMD64:
		kArch = OSARCH_X64;
		break;

	case PROCESSOR_ARCHITECTURE_INTEL:
		kArch = OSARCH_X86;
		break;

	case PROCESSOR_ARCHITECTURE_ARM:
		kArch = OSARCH_ARM;
		break;

	case PROCESSOR_ARCHITECTURE_ARM64:
		kArch = OSARCH_ARM64;
		break;

	case PROCESSOR_ARCHITECTURE_IA64:
		kArch = OSARCH_IA64;
		break;

	case PROCESSOR_ARCHITECTURE_UNKNOWN:
		kArch = OSARCH_UNKNOWN;
		break;

	default:
		break;
	}

	SecureZeroMemory(&OSinfo2, sizeof(SYSTEM_INFO));

	switch (dwOption)
	{
	case 0:
		GetSystemTime(&sTime);
		wprintf(
			L"    __ __ ____  __           __\n"
			L"   / //_// __ )/ /___ ______/ /_\t| KBlast client - OS Build #%d - Major version #%d\n"
			L"  / ,<  / __  / / __ `/ ___/ __/\t| Version : %s ( first release ) - Architecture : %s\n"
			L" / /| |/ /_/ / / /_/ (__  ) /_\t\t| Website : http://www.github.com/lem0nSec/KBlast\n"
			L"/_/ |_/_____/_/\\__,_/____/\\__/\t\t| Author  : < lem0nSec_@world:~$ >\n"
			L"------------------------------------------------------->>>\n", OSinfo.dwBuildNumber, OSinfo.dwMajorVersion, KBLAST_VERSION, KBLAST_ARCH
		);
		break;

	case 1:
		GetSystemTime(&sTime);
		wprintf(L"System time is : %d:%d:%d - %d/%d/%d\n", sTime.wHour, sTime.wMinute, sTime.wSecond, sTime.wMonth, sTime.wDay, sTime.wYear);
		break;

	case 2:
		wprintf(L"Microsoft Windows NT %d.%d OS Build %d ( Arch %s )\nKBlast v%s ( Arch %s )\n", OSinfo.dwMajorVersion, OSinfo.dwMinorVersion, OSinfo.dwBuildNumber, kArch, KBLAST_VERSION, KBLAST_ARCH);
		break;

	default:
		break;
	}

}

BOOL KBlast_c_CheckOSVersion()
{
	BOOL status = FALSE;
	HMODULE ntdll = 0;
	PRTLGETVERSION RtlGetVersion = 0;

	if (OSinfo.dwOSVersionInfoSize == 0)
	{
		OSinfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
		ntdll = GetModuleHandleW(L"ntdll.dll");
		if (ntdll != 0)
		{
			RtlGetVersion = (PRTLGETVERSION)GetProcAddress(ntdll, "RtlGetVersion");
			if (RtlGetVersion != 0)
			{
				RtlGetVersion(&OSinfo);
			}
		}
	}

	if ((OSinfo.dwBuildNumber == 19045) && (OSinfo.dwMajorVersion == 10))
	{
		status = TRUE;
	}

	return status;

}

BOOL KBlast_c_init()
{
	BOOL initStatus = FALSE;
	DWORD szServiceInit = KBLAST_SD_FAILED;
	BOOL adminStatus = FALSE;

	adminStatus = KBlast_c_CheckTokenIntegrity();
	if (adminStatus == TRUE)
	{
		szServiceInit = KBlast_c_ServiceInitialize(SERVICE_CREATE_AND_LOAD);
		switch (szServiceInit)
		{
		case KBLAST_SD_SUCCESS:
			initStatus = TRUE;
			//wprintf(L"[+] Driver up.\n");
			break;

		case KBLAST_SD_FAILED:
			wprintf(L"[-] Service registration failed.\n");
			break;

		case KBLAST_D_SUCCESS:
			initStatus = TRUE;
			//wprintf(L"[+] Driver up.\n");
			break;

		case KBLAST_D_FAILED:
			wprintf(L"[-] Driver down.\n");
			break;

		case KBLAST_SD_EXIST:
			initStatus = TRUE;
			//wprintf(L"[+] Driver up.\n");
			break;

		case KBLAST_BINARY_NOT_FOUND:
			wprintf(L"[-] %s not found.\n", KBLAST_DRV_BINARY);
			break;

		case KBLAST_BINARY_ERROR_GENERIC:
			wprintf(L"[-] %s error generic.\n", KBLAST_DRV_BINARY);
			break;

		default:
			break;
		}
	}
	else
	{
		wprintf(L"[-] Insufficient privileges. Quitting...\n");
	}

	return initStatus;

}


BOOL KBlast_c_cleanup()
{
	BOOL status = FALSE;
	DWORD szServiceStatus = KBLAST_SD_EXIST;
	BOOL adminStatus = FALSE;


	adminStatus = KBlast_c_CheckTokenIntegrity();
	if (adminStatus == TRUE)
	{
		szServiceStatus = KBlast_c_ServiceInitialize(SERVICE_UNLOAD_AND_DELETE);
		if (szServiceStatus != KBLAST_SD_SUCCESS)
		{
			wprintf(L"[-] Failed to unload driver\n");
		}
	}

	return status;

}


void KBlast_c_ConsoleInit()
{
	SetConsoleTitle(KBLAST_CLT_TITLE);
	KBlast_c_GetInfo(0);
}


BOOL KBlast_c_system(wchar_t* input)
{
	BOOL status = FALSE;
	char* systemInput = 0;

	systemInput = KBlast_c_utils_UnicodeStringToAnsiString(input);
	if (systemInput != 0)
	{
		system((char*)((DWORD_PTR)systemInput + 1));
		status = TRUE;
	}

	KBlast_c_utils_FreeAnsiString(systemInput);

	return status;

}


BOOL KBlast_c_ConsoleStart()
{
	BOOL status = FALSE;
	KBlast_c_ConsoleInit();

	if (KBlast_c_CheckOSVersion() == FALSE)
	{
		wprintf(L"[!] Warning : This OS version might not be fully supported. Critical issues may rise.\n");
	}

	wchar_t input[MAX_PATH];
	while (TRUE)
	{
		wprintf(L"\n[ KBlast ] --> ");
		fgetws(input, ARRAYSIZE(input), stdin); fflush(stdin);
		if (wcscmp(input, L"help\n") == 0)
		{
			KBlast_c_module_help(GENERIC);
		}
		else if (wcscmp(input, L"quit\n") == 0)
		{
			wprintf(L"bye!\n");
			break;
		}
		else if (wcscmp(input, L"banner\n") == 0)
		{
			KBlast_c_GetInfo(0);
		}
		else if (wcscmp(input, L"cls\n") == 0)
		{
			system("cls");
		}
		else if (wcscmp(input, L"pid\n") == 0)
		{
			wprintf(L"PID : %d\n", GetCurrentProcessId());
		}
		else if (wcsncmp(input, L"!", 1) == 0)
		{
			status = KBlast_c_system(input);
		}
		else if (wcscmp(input, L"time\n") == 0)
		{
			KBlast_c_GetInfo(1);
		}
		else if (wcscmp(input, L"version\n") == 0)
		{
			KBlast_c_GetInfo(2);
		}
		else if (wcsncmp(input, KBLAST_MOD_MISC, wcslen(KBLAST_MOD_MISC)) == 0)
		{
			KBlast_c_device_dispatch_misc(input);
		}
		else if (wcsncmp(input, KBLAST_MOD_BLOB, wcslen(KBLAST_MOD_BLOB)) == 0)
		{
			KBlast_c_device_dispatch_blob(input);
		}
		else if (wcsncmp(input, KBLAST_MOD_PROTECTION, wcslen(KBLAST_MOD_PROTECTION)) == 0)
		{
			KBlast_c_device_dispatch_protection(input);
		}
		else if (wcsncmp(input, KBLAST_MOD_TOKEN, wcslen(KBLAST_MOD_TOKEN)) == 0)
		{
			KBlast_c_device_dispatch_token(input);
		}
		else if (wcsncmp(input, KBLAST_MOD_CALLBACK, wcslen(KBLAST_MOD_CALLBACK)) == 0)
		{
			KBlast_c_device_dispatch_callbacks(input);
		}
		else if (wcsncmp(input, KBLAST_MOD_PROCESS, wcslen(KBLAST_MOD_PROCESS)) == 0)
		{
			KBlaster_c_device_dispatch_process(input);
		}
		else if (wcscmp(input, L"\n") == 0)
		{
			continue;
		}
		else
		{
			wprintf(L"[!] Command not found.\n");
			KBlast_c_module_help(GENERIC);
		}
	}

	return status;

}


BOOL wmain(int argc, wchar_t* argv[])
{
	if (argc < 2)
	{
		if (KBlast_c_init())
		{
			KBlast_c_ConsoleStart();
			return KBlast_c_cleanup();
		}
		else
			return FALSE;
	}
	else if (argc < 3)
	{
		if (wcscmp(argv[1], L"/?") == 0)
		{
			goto help;
		}
		else if (wcscmp(argv[1], L"/load") == 0) // load driver and exit
		{
			return KBlast_c_init();
		}
		else if (wcscmp(argv[1], L"/unload") == 0) // unload driver and exit
		{
			return KBlast_c_cleanup();
		}
	}

help:
	wprintf(
		L"Usage: %s {optional_argument}\n\n/load\t\t:\tload %s\n/unload\t\t:\tunload %s\n",
		argv[0], KBLAST_DRV_BINARY, KBLAST_DRV_BINARY
	);

	return TRUE;

}