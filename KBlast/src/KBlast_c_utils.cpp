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


int KBlast_c_utils_GetCommandLineArguments(IN char* inBuffer, IN BYTE separator, OUT PKBLAST_COMMANDLINE_ARGUMENTS pArgs)
{
	DWORD initialSize = 0, newSize = 0;
	//BYTE separator = 0x7C; // "|"
	int argc = 0;
	char* newBuffer = 0;

	if (inBuffer != 0)
	{
		initialSize = (DWORD)strlen(inBuffer);
		newBuffer = inBuffer;
		*(BYTE*)(BYTE*)((DWORD_PTR)newBuffer + initialSize - 1) = separator;
		for (DWORD i = 0; i < initialSize; i++)
		{
			if (*(BYTE*)(BYTE*)((DWORD_PTR)newBuffer + i) == separator)
			{
				*(BYTE*)(BYTE*)((DWORD_PTR)newBuffer + i) = 0x00;
			}
		}

		while (newSize <= initialSize)
		{
			if (pArgs->arg1 == NULL)
			{
				pArgs->arg1 = newBuffer;
				argc++;
			}
			else if (pArgs->arg2 == NULL)
			{
				pArgs->arg2 = newBuffer;
				argc++;
			}
			else if (pArgs->arg3 == NULL)
			{
				pArgs->arg3 = newBuffer;
				argc++;
			}
			else
			{
				break;
			}

			newSize += (DWORD)strlen(newBuffer);
			newBuffer = (char*)((DWORD_PTR)newBuffer + (DWORD)strlen(newBuffer) + 1);

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