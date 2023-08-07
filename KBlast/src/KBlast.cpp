#include "KBlast.hpp"



/*
* Launch procedure
* 1) Check if process has Administrator rights (check if SeLoadDriver is enabled?)
* 2) Check service status
* 3) Load driver
* 4) Start console
* 5) Close console
* 6) Driver/Service cleanup routine KBlast_c_cleanup()
*/


/*
* Modules (modules consists of command sets for interaction with the driver. They shouldn't support userland functionalities.)
* misc : bsod (generic)
* prot : protect,unprotect (process protection PPL)
* priv : enable,disable (token privileges)
* tokn : steal, restore (token management)
* call : process-list,thread-list,image-list (kernel callbacks)
*/

/*
* Basic commands (userland commands)
* quit (doesn't need explanation)
* banner (print kblast banner)
* !{OS command} (execute system command)
* health (perform healthcheck on the driver) TO BE IMPLEMENTED
*/




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
			wprintf(L"[+] Driver up.\n");
			break;

		case KBLAST_SD_FAILED:
			wprintf(L"[-] Service registration failed.\n");
			break;

		case KBLAST_D_SUCCESS:
			initStatus = TRUE;
			wprintf(L"[+] Driver up.\n");
			break;

		case KBLAST_D_FAILED:
			wprintf(L"[-] Driver down.\n");
			break;

		case KBLAST_SD_EXIST:
			initStatus = TRUE;
			wprintf(L"[+] Driver up.\n");
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
		if (szServiceStatus == KBLAST_SD_SUCCESS)
		{
			wprintf(L"[+] Success.\n");
		}
		else
		{
			wprintf(L"[-] Failed.\n");
		}

	}

	return status;

}


void KBlast_c_ConsoleInit()
{
	COORD topLeft = { 0, 0 };
	HANDLE hConsole = 0;
	CONSOLE_SCREEN_BUFFER_INFO cInfo = { 0 };
	DWORD dwWritten;

	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	GetConsoleScreenBufferInfo(hConsole, &cInfo);
	FillConsoleOutputCharacterW(hConsole, ' ', cInfo.dwSize.X, topLeft, &dwWritten);
	FillConsoleOutputCharacterW(hConsole, ' ', cInfo.dwSize.Y, topLeft, &dwWritten);
	SetConsoleCursorPosition(hConsole, topLeft);

	RtlZeroMemory(&cInfo, sizeof(CONSOLE_SCREEN_BUFFER_INFO));

	SetConsoleTitle(KBLAST_CLT_TITLE);
	wprintf(L"%s\n", KBlast_c_banner);

}


BOOL KBlast_c_userland_system(wchar_t* input)
{
	BOOL status = FALSE;
	char* systemInput = 0;

	systemInput = KBlast_c_utils_UnicodeStringToAnsiString(input);
	if (systemInput != 0)
	{
		system((char*)((DWORD_PTR)systemInput + 1));
		wprintf(L"\n");
		status = TRUE;
	}

	KBlast_c_utils_FreeAnsiString(systemInput);

	return status;

}



BOOL KBlast_c_ConsoleStart()
{
	BOOL status = FALSE;
	KBlast_c_ConsoleInit();

	wchar_t input[MAX_PATH];
	while (TRUE)
	{
		wprintf(L"KBlast > ");
		fgetws(input, ARRAYSIZE(input), stdin); fflush(stdin);
		if (wcscmp(input, L"quit\n") == 0)
		{
			wprintf(L"bye!\n");
			break;
		}
		if (wcscmp(input, L"banner\n") == 0)
		{
			wprintf(L"%s\n", KBlast_c_banner);
		}
		if (wcscmp(input, L"cls\n") == 0)
		{
			system("cls");
		}
		if (wcscmp(input, L"pid\n") == 0)
		{
			wprintf(L"PID : %d\n", GetCurrentProcessId());
		}
		if (wcsncmp(input, L"!", 1) == 0)
		{
			status = KBlast_c_userland_system(input);
		}
		if (wcsncmp(input, KBLAST_MOD_GENERIC, 5) == 0)
		{
			KBlast_c_device_dispatch_misc((wchar_t*)((DWORD_PTR)input + 10));
		}
		if (wcsncmp(input, KBLAST_MOD_PROTECTION, 5) == 0)
		{
			KBlast_c_device_dispatch_protection((wchar_t*)((DWORD_PTR)input + 10));
		}
		if (wcsncmp(input, KBLAST_MOD_PRIVILEGES, 5) == 0)
		{
			KBlast_c_device_dispatch_privileges((wchar_t*)((DWORD_PTR)input + 10));
		}
		if (wcsncmp(input, KBLAST_MOD_TOKEN, 5) == 0)
		{
			KBlast_c_device_dispatch_token((wchar_t*)((DWORD_PTR)input + 10));
		}
		if (wcsncmp(input, KBLAST_MOD_CALLBACK, 5) == 0)
		{
			KBlast_c_device_dispatch_callbacks((wchar_t*)((DWORD_PTR)input + 10));
		}
		/*
		else
		{
			KBlast_c_userland_dispatch(input);
		}
		*/
	}

	return status;

}


int wmain(int argc, wchar_t* argv[])
{
	BOOL status = FALSE;
	BOOL start = TRUE;

	if (argc < 2)
	{
		status = KBlast_c_init();
		if (status == TRUE)
		{
			wprintf(L"[+] Starting console...\n");
			Sleep(1000);
			KBlast_c_ConsoleStart(); // see if it could be the case to create a new thread here and put the main thread to sleep
			KBlast_c_cleanup();		// the main thread should be awaken when it's time to clean up and exit
		}
	}
	if (argc < 3)
	{
		start = FALSE;
		if (wcscmp(argv[1], L"/load") == 0) // load driver and exit
		{
			status = KBlast_c_init();
		}
		if (wcscmp(argv[1], L"/unload") == 0) // unload driver and exit
		{
			status = KBlast_c_cleanup();
		}
	}

	return status;

}