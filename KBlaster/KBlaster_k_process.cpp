#include "KBlaster_k_process.hpp"

NTSTATUS KBlaster_k_ProcessEnumerate()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEprocess = 0;
	PLIST_ENTRY ActiveProcessLinks = 0;
	PVOID link = 0, pid = 0;

	pEprocess = PsInitialSystemProcess;
	ActiveProcessLinks = (PLIST_ENTRY)((ULONG_PTR)pEprocess + EPROCESS_ACTIVEPROCESSLINKS_OFFSET[KBlaster_k_utils_GetWindowsVersion()]);
	while (TRUE)
	{
		pid = (PVOID)((ULONG_PTR)ActiveProcessLinks->Flink - 8);
		DbgPrint("0x%-016p\n", pid);
		pEprocess = (PEPROCESS)((ULONG_PTR)ActiveProcessLinks->Flink - EPROCESS_ACTIVEPROCESSLINKS_OFFSET[KBlaster_k_utils_GetWindowsVersion()]);
		if (pEprocess == PsInitialSystemProcess)
		{
			break;
		}
	}

	return STATUS_SUCCESS;

}