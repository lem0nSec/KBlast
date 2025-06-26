/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "Kblast_string.hpp"


void Kblast_string_FreeAnsiString(_In_ PANSI_STRING pAnsiString)
{
	if (!pAnsiString ||
		!pAnsiString->Buffer) {
		return;
	}

	RtlFreeAnsiString(pAnsiString);
}


BOOL Kblast_string_CreateAnsiStringFromUnicodeString(
	_In_ PUNICODE_STRING pUnicodeString,
	_Out_ PANSI_STRING pAnsiString)
{
	BOOL status = FALSE;

	if (!pUnicodeString ||
		!pAnsiString) {
		goto Exit;
	}

	if (!NT_SUCCESS(RtlUnicodeStringToAnsiString(pAnsiString, pUnicodeString, TRUE))) {
		goto Exit;
	}

	status = TRUE;

Exit:
	return status;
}


BOOL Kblast_string_CommandSearch(
	_In_ LPCWSTR Input,
	_In_ PKBL_COMMAND pArray,
	_In_ SIZE_T szArray,
	_Inout_ PDWORD Index)
{
	BOOL status = FALSE;
	DWORD result = 0xff;
	DWORD iterator = 0;

	for (iterator = 0; iterator < szArray; iterator++) {
		if (!wcsncmp(
			Input, 
			pArray[iterator].lpCommand, 
			wcslen(pArray[iterator].lpCommand))
			) {
			*Index = iterator;
			status = TRUE;
			break;
		}
	}

	return status;
}

void Kblast_string_AdjustInputCommandString(
	_In_ LPCWSTR InputCommandString)
{
	SIZE_T szInput = 0;
	DWORD i = 0;

	if (!InputCommandString) {
		return;
	}

	szInput = wcslen(InputCommandString);
	if (!szInput) {
		return;
	}

	for (i = 0; i < szInput; i++) {
		if (*(PBYTE)(InputCommandString + i) == 0x0A) {
			*(PBYTE)(InputCommandString + i) = 0x00;
		}
	}

	return;
}


BOOL Kblast_p_string_GetCommandLineArguments(
	_In_ char* CommandLine, 
	_Inout_ PKBL_MODULE_COMMANDLINE pArguments)
{
	BOOL status = FALSE;

	SIZE_T szCommandLine = 0;
	DWORD i = 0;
	DWORD j = 0;
	DWORD k = 0;
	char* argStruct = 0;
	char* realArg = 0;


	if (!CommandLine ||
		!pArguments) {
		goto Exit;
	}

	for (i = 0; i < MAX_PATH; i++) {
		if (*(PBYTE)((PBYTE)CommandLine + i) == 0x20) {
			*(PBYTE)((PBYTE)CommandLine + i) = 0x7C;
		} else if (*(PBYTE)((PBYTE)CommandLine + i) == 0x0A) {
			break;
		}
	}

	szCommandLine = strlen(CommandLine);
	for (i = 0; i < szCommandLine; i++) {
		if (*(PBYTE)((PBYTE)CommandLine + i) == 0x2F) {
			pArguments->NumberOfArguments++;
		}
		else if (*(PBYTE)((PBYTE)CommandLine + i) == 0x0A) {
			break;
		}
	}

	for (i = 0; i < szCommandLine; i++) {
		if (*(PBYTE)((PBYTE)CommandLine + i) == 0x2F) {
			argStruct = (char*)((PBYTE)CommandLine + i + 1);
			for (j = 0; j < szCommandLine; j++) {
				if (*(PBYTE)((PBYTE)argStruct + j) == 0x3A) {
					*(PBYTE)((PBYTE)argStruct + j) = 0x00;
					realArg = (char*)((PBYTE)argStruct + j + 1);
					for (k = 0; k < szCommandLine; k++) {
						if (*(PBYTE)((PBYTE)realArg + k) == 0x0A ||
							(*(PBYTE)((PBYTE)realArg + k) == 0x20) ||
							(*(PBYTE)((PBYTE)realArg + k) == 0x7C)) {
							*(PBYTE)((PBYTE)realArg + k) = 0x00;
							break;
						}
					}
					if (strcmp(argStruct, "action") == 0) {
						pArguments->Commandline.Action = (LPCSTR)realArg;
					}
					else if (strcmp(argStruct, "type") == 0) {
						pArguments->Commandline.Type = (LPCSTR)realArg;
					}
					else if (strcmp(argStruct, "blob") == 0) {
						pArguments->Commandline.blob = (LPCSTR)realArg;
					}
					else if (strcmp(argStruct, "container") == 0) {
						pArguments->Commandline.container = (DWORD)atoi(realArg);
					}
					else if (strcmp(argStruct, "size") == 0) {
						pArguments->Commandline.size = (SIZE_T)atoi(realArg);
					}
					else if (strcmp(argStruct, "pid") == 0) {
						pArguments->Commandline.ProcessId = (ULONG)atoi(realArg);
					}
					else if (strcmp(argStruct, "targetpid") == 0) {
						pArguments->Commandline.TargetProcessId = (ULONG)atoi(realArg);
					}
					else if (strcmp(argStruct, "value") == 0) {
						pArguments->Commandline.Value = Kblast_string_StringToPointer((LPCSTR)realArg);
					}
					else if (strcmp(argStruct, "name") == 0) {
						pArguments->Commandline.name = (LPCSTR)realArg;
					}
					argStruct = (char*)((PBYTE)realArg + strlen(realArg));
					realArg = 0;
					j = 0;
					
					status = TRUE;
					break;
				}
			}
		}
	}

Exit:
	return status;
}


BOOL Kblast_string_ParseCommandline(
	_In_ wchar_t* Commandline,
	_Inout_ PKBL_MODULE_COMMANDLINE pArguments)
{
	BOOL status = FALSE;

	UNICODE_STRING UnicodeString = { 0 };
	ANSI_STRING AnsiString = { 0 };

	if (!pArguments) {
		SetLastError(ERROR_INVALID_PARAMETER);
		goto Exit;
	}

	RtlInitUnicodeString(&UnicodeString, Commandline);

	status = Kblast_string_CreateAnsiStringFromUnicodeString(&UnicodeString, &AnsiString);
	if (!status) {
		goto Exit;
	}

	status = Kblast_p_string_GetCommandLineArguments(AnsiString.Buffer, pArguments);
	if (!status) {
		goto Exit;
	}


Exit:
	if (AnsiString.Buffer) {
		Kblast_string_FreeAnsiString(&AnsiString);
	}

	return status;
}


PVOID Kblast_string_StringToPointer(_In_ LPCSTR StringPointer)
{
	unsigned long long val = strtoull(StringPointer, NULL, 0);
	return (void*)(uintptr_t)val;
}

const char* Kblast_string_GetImageNameByFullPath(_In_ const char* FullImagePath) {
	const char* filename = strrchr(FullImagePath, '\\');
	
	if (filename == NULL) {
		filename = FullImagePath; // No backslash found, assume full_path is the filename
	}
	else {
		filename++; // Move past the '\'
	}
	return filename;
}

/*
char* Kblast_string_GetImageNameByFullPath(_In_ char* FullImagePath)
{
	BYTE separator = 0x5C;
	DWORD i = 0;
	char* endPath = (char*)((DWORD_PTR)FullImagePath + strlen(FullImagePath));
	DWORD len = (DWORD)strlen(FullImagePath);

	for (i = len; i != 0; i--) {
		if (*(BYTE*)(BYTE*)((DWORD_PTR)FullImagePath + i) == separator) {
			break;
		}
	}

	return (char*)((DWORD_PTR)FullImagePath + i + 1);
}
*/

BOOL Kblast_string_ConvertStringToHexBlob(
	_In_ LPCSTR StringBlob,
	_Inout_ LPVOID Blob,
	_Inout_ PDWORD ReturnLength)
{
	BOOL status = FALSE;
	DWORD dwBlobLength = (DWORD)strlen(StringBlob);
	LPVOID local = 0;

	if (strlen(StringBlob) > 250) {
		SetLastError(ERROR_BUFFER_OVERFLOW);
		goto Exit;
	}

	status = CryptStringToBinaryA(
		StringBlob,
		strlen(StringBlob),
		CRYPT_STRING_HEX,
		static_cast<BYTE*>(Blob),
		&dwBlobLength,
		NULL,
		NULL);

	if (status) {
		*ReturnLength = dwBlobLength;
	}

Exit:

	return status;
}

void Kblast_string_HexDump(
	_In_ const void* data, 
	_In_ SIZE_T size)
{
	char ascii[17] = { 0 };
	SIZE_T i = 0, j = 0;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i)
	{
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~')
		{
			ascii[i % 16] = ((unsigned char*)data)[i];
		}
		else
		{
			ascii[i % 16] = '.';
		}
		if ((i + 1) % 8 == 0 || i + 1 == size)
		{
			printf(" ");
			if ((i + 1) % 16 == 0)
			{
				printf("|  %s \n", ascii);
			}
			else if (i + 1 == size)
			{
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8)
				{
					printf(" ");
				}
				for (j = (i + 1) % 16; j < 16; ++j)
				{
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}
