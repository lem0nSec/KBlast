/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlast_c_utils.hpp"



ANSI_STRING aBuffer = { 0 };

char* KBlast_c_utils_UnicodeStringToAnsiString(IN wchar_t* input)
{
	UNICODE_STRING uBuffer = { 0 };
	NTSTATUS cStatus = 0;

	RtlInitUnicodeString(&uBuffer, input);
	cStatus = RtlUnicodeStringToAnsiString(&aBuffer, &uBuffer, TRUE);
	RtlZeroMemory(&uBuffer, sizeof(UNICODE_STRING));

	return aBuffer.Buffer;

}


int KBlast_c_utils_GetCommandlineArguments(IN char* inBuffer, OUT PKBLAST_COMMANDLINE_ARGUMENTS pArgs)
{
	SIZE_T szInitial = 0;
	DWORD i = 0, j = 0, k = 0;
	char* argStruct = 0;
	char* realArg = 0;
	int argc = 0;

	if (inBuffer != 0)
	{
		for (i = 0; i < MAX_PATH; i++)
		{
			if (*(PBYTE)((PBYTE)inBuffer + i) == 0x20)
			{
				*(PBYTE)((PBYTE)inBuffer + i) = 0x7C;
			}
			else if (*(PBYTE)((PBYTE)inBuffer + i) == 0x0A)
			{
				break;
			}
		}

		szInitial = strlen(inBuffer);
		for (i = 0; i < szInitial; i++)
		{
			if (*(PBYTE)((PBYTE)inBuffer + i) == 0x2F) // "/"
			{
				argc++;
			}
			else if (*(PBYTE)((PBYTE)inBuffer + i) == 0x0A)
			{
				break;
			}
		}

		for (i = 0; i < szInitial; i++)
		{
			if (*(PBYTE)((PBYTE)inBuffer + i) == 0x2F)
			{
				argStruct = (char*)((PBYTE)inBuffer + i + 1);
				for (j = 0; j < szInitial; j++)
				{
					if (*(PBYTE)((PBYTE)argStruct + j) == 0x3A) // ":"
					{
						*(PBYTE)((PBYTE)argStruct + j) = 0x00;
						realArg = (char*)((PBYTE)argStruct + j + 1);
						for (k = 0; k < szInitial; k++)
						{
							if (*(PBYTE)((PBYTE)realArg + k) == 0x0A || (*(PBYTE)((PBYTE)realArg + k) == 0x20) || (*(PBYTE)((PBYTE)realArg + k) == 0x7C))
							{
								*(PBYTE)((PBYTE)realArg + k) = 0x00;
								break;
							}
						}
						if (strcmp(argStruct, "action") == 0)
						{
							pArgs->action = (LPCSTR)realArg;
						}
						else if (strcmp(argStruct, "type") == 0)
						{
							pArgs->type = (LPCSTR)realArg;
						}
						else if (strcmp(argStruct, "blob") == 0)
						{
							pArgs->blob = (LPCSTR)realArg;
						}
						else if (strcmp(argStruct, "container") == 0)
						{
							pArgs->container = (DWORD)atoi(realArg);
						}
						else if (strcmp(argStruct, "size") == 0)
						{
							pArgs->size = (SIZE_T)atoi(realArg);
						}
						else if (strcmp(argStruct, "pid") == 0)
						{
							pArgs->pid = (ULONG)atoi(realArg);
						}
						else if (strcmp(argStruct, "targetpid") == 0)
						{
							pArgs->targetpid = (ULONG)atoi(realArg);
						}
						else if (strcmp(argStruct, "pointer") == 0)
						{
							pArgs->pointer = KBlast_c_utils_StringToKernelPointer((LPCSTR)realArg, (DWORD)strlen(realArg));
						}
						else if (strcmp(argStruct, "name") == 0)
						{
							pArgs->name = (LPCSTR)realArg;
						}
						argStruct = (char*)((PBYTE)realArg + strlen(realArg));
						realArg = 0;
						j = 0;
						break;
					}
				}
			}
		}
	}

	return argc;
		
}

void KBlast_c_utils_FreeAnsiString(IN char* ansiString)
{
	if ((ansiString == aBuffer.Buffer) && (aBuffer.Length != 0))
	{
		RtlFreeAnsiString(&aBuffer);
	}
}


char* KBlast_c_utils_GetImageNameByFullPath(char* FullImagePath)
{
	BYTE separator = 0x5C;
	DWORD i = 0;
	char* endPath = (char*)((DWORD_PTR)FullImagePath + strlen(FullImagePath));
	DWORD len = (DWORD)strlen(FullImagePath);

	for (i = len; i != 0; i--)
	{
		if (*(BYTE*)(BYTE*)((DWORD_PTR)FullImagePath + i) == separator)
		{
			break;
		}
	}

	return (char*)((DWORD_PTR)FullImagePath + i + 1);

}


PVOID KBlast_c_utils_StringToKernelPointer(LPCSTR strPointer, DWORD szPtr)
{
	BYTE* buf = 0;
	BYTE* newBuf = 0;
	DWORD szBlob = szPtr;
	DWORD pcbBinary = szBlob;
	DWORD szForLoop = sizeof(PVOID);
	DWORD i = 0;
	PVOID res = 0;
	
	buf = (BYTE*)LocalAlloc(LPTR, (szBlob));
	if (buf != 0)
	{
		if (CryptStringToBinaryA(strPointer, szBlob, CRYPT_STRING_HEX, buf, &pcbBinary, NULL, NULL) == TRUE)
		{
			newBuf = (BYTE*)((DWORD_PTR)buf + szBlob - 1);

			for (i = 0; i < szForLoop; i++)
			{
				*(PBYTE)((DWORD_PTR)newBuf - i) = *(BYTE*)(BYTE*)((DWORD_PTR)buf + i);
			}
			
			memcpy(buf, (const void*)((DWORD_PTR)buf + szForLoop), szForLoop);
			memset((void*)((DWORD_PTR)buf + szForLoop), 0, szForLoop);
			res = (PVOID)*(PVOID*)(PVOID*)buf;
			LocalFree(buf);
		}
	}
	
	return res;

}


DWORD KBlast_c_utils_GetProcessIdByName(const wchar_t* procName)
{
	DWORD result = 0;
	HANDLE hSnap = 0;
	PROCESSENTRY32W entry32 = { 0 };

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap)
	{
		entry32.dwSize = sizeof(PROCESSENTRY32W);
		if (Process32First(hSnap, &entry32))
		{
			while (Process32Next(hSnap, &entry32))
			{
				if (_wcsicmp(entry32.szExeFile, procName) == 0)
				{
					result = entry32.th32ProcessID;
					break;
				}
			}
			SecureZeroMemory(&entry32, sizeof(PROCESSENTRY32W));
		}
		CloseHandle(hSnap);
	}

	return result;

}


// procInfo is required to have the 'processID' value set to a valid pid
BOOL KBlast_c_utils_ListProcessInformation(PKBLAST_USER_PROCESS_INFORMATION procInfo)
{
	BOOL status = FALSE;
	HANDLE hSnap = 0, hProcess = 0, hToken = 0;
	PROCESSENTRY32 pEntry32 = { 0 };
	DWORD retL = 0, nameUserLen = MAX_PATH, domainNameLen = MAX_PATH;
	wchar_t TokenDomain[MAX_PATH] = { 0 };
	wchar_t TokenName[MAX_PATH] = { 0 };
	PTOKEN_OWNER tOwner = NULL;
	SID_NAME_USE snu;

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		pEntry32.dwSize = (DWORD)sizeof(PROCESSENTRY32W);
		if (Process32First(hSnap, &pEntry32))
		{
			while (Process32Next(hSnap, &pEntry32))
			{
				if (pEntry32.th32ProcessID == procInfo->processID)
				{
					status = TRUE;
					wcsncpy_s(procInfo->ImageFileName, MAX_PATH, pEntry32.szExeFile, MAX_PATH);
					break;
				}
			}
		}

		if (status)
		{
			hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, procInfo->processID);
			if (hProcess != INVALID_HANDLE_VALUE)
			{
				OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
				if (hToken != INVALID_HANDLE_VALUE)
				{
					GetTokenInformation(hToken, TokenOwner, NULL, 0, &retL);
					if (retL > 0)
					{
						tOwner = (PTOKEN_OWNER)LocalAlloc(LPTR, (SIZE_T)retL);
						if (tOwner)
						{
							if (GetTokenInformation(hToken, TokenOwner, (LPVOID)tOwner, retL, &retL))
							{
								LookupAccountSidW(NULL, tOwner->Owner, TokenName, &nameUserLen, TokenDomain, &domainNameLen, &snu);
							}
						}
						SecureZeroMemory(tOwner, retL);
						LocalFree(tOwner);
					}
					CloseHandle(hToken);
				}
				CloseHandle(hProcess);
			}
			CloseHandle(hSnap);

			if ((wcslen(TokenName) == 0) || (wcslen(TokenDomain) == 0))
				wcsncpy_s(procInfo->TokenOwner, MAX_PATH, L"N/A", MAX_PATH);
			else
			{
				wcsncpy_s(procInfo->TokenOwner, MAX_PATH, TokenDomain, MAX_PATH);
				wcsncpy_s((wchar_t*)(procInfo->TokenOwner + wcslen(procInfo->TokenOwner)), MAX_PATH - wcslen(procInfo->TokenOwner), L"\\", MAX_PATH - wcslen(procInfo->TokenOwner));
				wcsncpy_s((wchar_t*)(procInfo->TokenOwner + wcslen(procInfo->TokenOwner)), MAX_PATH - wcslen(procInfo->TokenOwner), TokenName, MAX_PATH - wcslen(procInfo->TokenOwner));
			}
		}
	}

	return status;

}

LPVOID KBlast_c_utils_GetDeviceDriverBaseAddress(LPSTR DeviceDriverName)
{
	LPVOID tmp_array = 0;
	LPVOID result = 0;
	DWORD needed = 0, needed2 = 0;
	DWORD64 i = 0;
	char name[MAX_PATH];
	int j = 0;

	EnumDeviceDrivers(NULL, 0, &needed);
	if (needed > 0)
	{
		tmp_array = (LPVOID)LocalAlloc(LPTR, (SIZE_T)needed);
		if (tmp_array)
		{
			if (EnumDeviceDrivers((LPVOID*)tmp_array, needed, &needed2))
			{
				for (i = 0; i < needed / sizeof(LPVOID); i++)
				{
					GetDeviceDriverBaseNameA(*(PVOID*)(PVOID*)((PBYTE)tmp_array + (8 * i)), name, MAX_PATH);
					if (_stricmp(name, DeviceDriverName) == 0)
					{
						RtlCopyMemory(&result, (PBYTE)tmp_array + (8 * i), sizeof(LPVOID));
						break;
					}
				}
			}
			
			LocalFree(tmp_array);
		}
	}

	return result;

}