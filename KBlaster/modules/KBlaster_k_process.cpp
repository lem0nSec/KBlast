/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/

#include "KBlaster_k_process.hpp"


NTSTATUS KBlaster_k_ProcessList(OUT PVOID pProcInfo)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEprocess = 0;
	PLIST_ENTRY ActiveProcessLinks = 0;
	ULONG64 pid = 0;
	KBLASTER_FULL_PROCESS_INFORMATION* ProcInfo = (KBLASTER_FULL_PROCESS_INFORMATION*)pProcInfo;
	KBLASTER_PROCESS_INFORMATION* current_procInfo = 0;
	int generic_count = 0;
	char* ImageFileName = 0;

	if (KBlaster_k_utils_GetWindowsVersion() == WINDOWS_UNSUPPORTED)
	{
		status = STATUS_NOT_SUPPORTED;
		goto exit;
	}

	pEprocess = PsInitialSystemProcess;
	while (TRUE)
	{
		pid = *(PULONG64)((ULONG_PTR)pEprocess + EPROCESS_UNIQUEPROCESSID_OFFSET[KBlaster_k_utils_GetWindowsVersion()]);
		if (pid == 0)
		{
			ImageFileName = "System Idle Process";
		}
		else
		{
			ImageFileName = (char*)((ULONG_PTR)pEprocess + EPROCESS_IMAGEFILENAME_OFFSET[KBlaster_k_utils_GetWindowsVersion()]);
		}
		

		if (ProcInfo->ProcNumber != 0)
		{
			current_procInfo = (KBLASTER_PROCESS_INFORMATION*)((ULONG_PTR)ProcInfo->pProcInformation + (sizeof(KBLASTER_PROCESS_INFORMATION) * generic_count));
			current_procInfo->Eprocess = pEprocess;
			current_procInfo->UniqueProcessId = pid;
			current_procInfo->Token = *(PVOID*)((ULONG_PTR)pEprocess + EPROCESS_TOKEN_OFFSET[KBlaster_k_utils_GetWindowsVersion()]);
			strncpy((char*)current_procInfo->ImageFileName, /* (char*)((ULONG_PTR)pEprocess + EPROCESS_IMAGEFILENAME_OFFSET[KBlaster_k_utils_GetWindowsVersion()]), */ ImageFileName, sizeof(current_procInfo->ImageFileName) - 1);
			RtlCopyMemory(&current_procInfo->ProtectionInformation, (PPROCESS_PROTECTION_INFO)((ULONG_PTR)pEprocess + EPROCESS_SIGNATURE_LEVEL_OFFSET[KBlaster_k_utils_GetWindowsVersion()]), sizeof(PROCESS_PROTECTION_INFO));
		}

		generic_count++;
		
		ActiveProcessLinks = (PLIST_ENTRY)((ULONG_PTR)pEprocess + EPROCESS_ACTIVEPROCESSLINKS_OFFSET[KBlaster_k_utils_GetWindowsVersion()]);
		pEprocess = (PEPROCESS)((ULONG_PTR)ActiveProcessLinks->Flink - EPROCESS_ACTIVEPROCESSLINKS_OFFSET[KBlaster_k_utils_GetWindowsVersion()]);
		
		if (pEprocess == PsInitialSystemProcess)
		{
			break;
		}
	}

	if (ProcInfo->ProcNumber == 0)
	{
		ProcInfo->ProcNumber = generic_count;
	}
	if (ProcInfo->ProcNumber != 0)
	{
		status = STATUS_SUCCESS;
	}

exit:

	return status;

}


NTSTATUS KBlaster_k_ProcessTerminate(IN ULONG processID)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE hkHandle = 0;
	OBJECT_ATTRIBUTES objAttr = { 0 };
	CLIENT_ID clId = { 0 };
	PEPROCESS pEprocess = 0;
	
	if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)processID, &pEprocess)))
	{
		ObDereferenceObject(pEprocess);
		InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		clId.UniqueProcess = (HANDLE)processID;
		clId.UniqueThread = NULL;
		if (NT_SUCCESS(ZwOpenProcess(&hkHandle, PROCESS_ALL_ACCESS, &objAttr, &clId)) && (hkHandle != 0))
		{
			status = ZwTerminateProcess(hkHandle, 0);
			status = ZwClose(hkHandle);
		}
	}

	return status;

}


/*
NTSTATUS KBlaster_k_ProcessUnlink(IN ULONG UniqueProcessId)
{
	//NTSTATUS status = STATUS_UNSUCCESSFUL;
	PLIST_ENTRY pActiveProcessLinks = 0;
	PEPROCESS pEprocess = 0, pEprocess_now = 0;

	DbgPrint("%d\n", (int)UniqueProcessId);
	DbgBreakPoint();
	pEprocess_now = PsInitialSystemProcess;
	if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)UniqueProcessId, &pEprocess)))
	{
		while (TRUE)
		{
			pActiveProcessLinks = (PLIST_ENTRY)((ULONG_PTR)pEprocess_now + EPROCESS_ACTIVEPROCESSLINKS_OFFSET[KBlaster_k_utils_GetWindowsVersion()]);
			pEprocess_now = (PEPROCESS)((ULONG_PTR)pActiveProcessLinks->Flink - EPROCESS_ACTIVEPROCESSLINKS_OFFSET[KBlaster_k_utils_GetWindowsVersion()]);
			if (pEprocess_now == pEprocess)
			{
				DbgPrint("[+] Found.\n");
				pEprocess_now = (PEPROCESS)((ULONG_PTR)pActiveProcessLinks->Blink - EPROCESS_ACTIVEPROCESSLINKS_OFFSET[KBlaster_k_utils_GetWindowsVersion()]);
				pActiveProcessLinks = (PLIST_ENTRY)((ULONG_PTR)pEprocess_now + EPROCESS_ACTIVEPROCESSLINKS_OFFSET[KBlaster_k_utils_GetWindowsVersion()]);
				*(PVOID*)&pActiveProcessLinks->Flink = *(PVOID*)&pActiveProcessLinks->Flink->Flink;
				pActiveProcessLinks = (PLIST_ENTRY)((ULONG_PTR)pEprocess_now + EPROCESS_ACTIVEPROCESSLINKS_OFFSET[KBlaster_k_utils_GetWindowsVersion()]);
				pEprocess_now = (PEPROCESS)((ULONG_PTR)pActiveProcessLinks->Flink - EPROCESS_ACTIVEPROCESSLINKS_OFFSET[KBlaster_k_utils_GetWindowsVersion()]);
				*(PVOID*)&pActiveProcessLinks->Blink = *(PVOID*)&pActiveProcessLinks->Blink->Blink;

				//*(PVOID*)&pActiveProcessLinks->Blink = *(PVOID*)&pActiveProcessLinks->Flink->Flink;
				
				//status = STATUS_SUCCESS;
				break;
			}
		}

		ObDereferenceObject(pEprocess);

	}

	return STATUS_SUCCESS;

}
*/