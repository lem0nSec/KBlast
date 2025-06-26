/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlaster_k_callbacks.hpp"


// This function needs major improvements.
// Not having time for now.
// Tested on 19045 to 22631 and it works.
// It likely fails on older versions.
__declspec(code_seg("PAGE"))
static
NTSTATUS KBlaster_p_callback_GetCallbackEntryPoint(
	_In_ CallbackType cType, 
	_Out_ PVOID * pEntryPoint)
{
	PAGED_CODE();

	NTSTATUS status = 1;
	ULONG64 pInitialFunction = 0;
	ULONG64 pInnerFunction = 0;
	ULONG64 i, offset = 0;
	UCHAR initialOpcode1 = 0xE8, initialOpcode2 = 0xE9;
	UCHAR innerOpcode1 = 0, innerOpcode2 = 0;
	UNICODE_STRING initialFunctionName = { 0, 0, 0 };


	if (!pEntryPoint) {
		status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}
	*pEntryPoint = 0;

	switch (cType)
	{
	case ProcessNotify:
		RtlInitUnicodeString(&initialFunctionName, L"PsSetCreateProcessNotifyRoutine");
		pInitialFunction = (ULONG64)MmGetSystemRoutineAddress(&initialFunctionName);
		innerOpcode1 = 0x4C;
		innerOpcode2 = 0x8D;
		break;

	case ThreadNotify:
		RtlInitUnicodeString(&initialFunctionName, L"PsSetCreateThreadNotifyRoutine");
		pInitialFunction = (ULONG64)MmGetSystemRoutineAddress(&initialFunctionName);
		innerOpcode1 = 0x48;
		innerOpcode2 = 0x8D;
		break;

	case ImageNotify:
		RtlInitUnicodeString(&initialFunctionName, L"PsSetLoadImageNotifyRoutine");
		pInitialFunction = (ULONG64)MmGetSystemRoutineAddress(&initialFunctionName);
		innerOpcode1 = 0x48;
		innerOpcode2 = 0x8D;
		break;

	case RegistryCallback:
		RtlInitUnicodeString(&initialFunctionName, L"CmUnRegisterCallback");
		pInitialFunction = (ULONG64)MmGetSystemRoutineAddress(&initialFunctionName);
		initialOpcode1 = 0x48;
		initialOpcode2 = 0x8D;
		break;

	case ObjectCallbacks:
	case FilterCallback:
	case NetworkCallback:
		status = STATUS_NOT_IMPLEMENTED;
		break;

	default:
		break;
	}

	if ((cType == ProcessNotify) ||
		(cType == ThreadNotify) ||
		(cType == ImageNotify)) {
		if (!pInitialFunction) {
			status = STATUS_UNSUCCESSFUL;
			goto Exit;
		}

		for (i = pInitialFunction; i < pInitialFunction + 0x70; i++) {
			if ((*(PUCHAR)i == initialOpcode1) ||
				(*(PUCHAR)i == initialOpcode2)) {
				RtlCopyMemory(&offset, (PUCHAR)i + 1, 4);
				pInnerFunction = i + offset + 5;

				for (i = pInnerFunction; i < pInnerFunction + 0x70; i++) {
					if ((*(PUCHAR)i == innerOpcode1) && (*((PUCHAR)i + 1) == innerOpcode2)) {
						offset = 0;
						RtlCopyMemory(&offset, (PUCHAR)i + 3, 4);
						*pEntryPoint = (PVOID)(i + offset + 7);
						status = STATUS_SUCCESS;
						goto Exit;
					}
				}
			}
		}
	}
	else if (cType == RegistryCallback) {
		if (!pInitialFunction) {
			status = STATUS_UNSUCCESSFUL;
			goto Exit;
		}

		for (i = pInitialFunction; i < (pInitialFunction + 150); i++) {
			if ((*(PUCHAR)i == initialOpcode1) && 
					(*((PUCHAR)i + 1) == initialOpcode2) && 
				(((*((PUCHAR)i + 2) >> 4) & 0xff) == 0)
				) {
				RtlCopyMemory(&offset, (PUCHAR)i + 3, 4);
				*pEntryPoint = (PVOID)(i + offset + 7);
				status = STATUS_SUCCESS;
				goto Exit;
			}
		}
	}


Exit:

	return status;
}


__declspec(code_seg("PAGE"))
static
void Kblaster_p_callback_GetNotifyRoutineModuleInformation(
	_In_ PKBLR_ASSIST_MODULE_EXTENDED_INFORMATION pAllModules, 
	_In_ PVOID Routine, 
	_Inout_ PROUTINE_MODULE_INFORMATION RoutineModuleInformation)
{
	PAGED_CODE();

	ULONG thismodule = 0;

	for (thismodule = 0; thismodule < pAllModules->NumberOfModules; thismodule++) {
		if ((Routine > pAllModules->AllModulesInformation[thismodule].BasicInfo.ImageBase) &&
			(Routine < 
				Add2Ptr(pAllModules->AllModulesInformation[thismodule].BasicInfo.ImageBase, 
					pAllModules->AllModulesInformation[thismodule].ImageSize)
				)
			) {
			RoutineModuleInformation->ModuleBase = pAllModules->AllModulesInformation[thismodule].BasicInfo.ImageBase;
			RoutineModuleInformation->ModuleImageSize = pAllModules->AllModulesInformation[thismodule].ImageSize;
			RoutineModuleInformation->ModuleFileNameOffset = pAllModules->AllModulesInformation[thismodule].FileNameOffset;
			RtlCopyMemory(RoutineModuleInformation->ModuleFullPathName, pAllModules->AllModulesInformation[thismodule].FullPathName, AUX_KLIB_MODULE_PATH_LEN);
			break;
		}
	}
}


__declspec(code_seg("PAGE"))
static
NTSTATUS Kblaster_p_callback_GetObjectCallbacksEntriesInfo(
	_Inout_opt_ PKBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION pObjectListEntriesInfo,
	_In_ ULONG ulObjectListEntriesInfoLength,
	_Inout_ PULONG ulReturnLength)
{
	PAGED_CODE();


	NTSTATUS status = 1;
	KBLR_ASSIST_MODULE_EXTENDED_INFORMATION pAllModulesInformation = { 0 };
	ULONG ulNumberOfRoutines = 0;
	ULONG ulIterator = 0;

	POBJECT_TYPE_23H2 pProcessType = static_cast<POBJECT_TYPE_23H2>(*(PVOID*)(*PsProcessType));
	POBJECT_TYPE_23H2 pThreadType = static_cast<POBJECT_TYPE_23H2>(*(PVOID*)(*PsThreadType));
	POBJECT_TYPE_23H2 pExDesktopType = static_cast<POBJECT_TYPE_23H2>(*(PVOID*)(*ExDesktopObjectType));
	POB_CALLBACK_ENTRY pCallbackEntry = nullptr;
	PVOID pEntryHead = nullptr;


	// There's probably no need to acquire a push lock here
	// The system has its own push lock when accessing callbacks of any kind here (object, notify routines, registry, etc...)
	// I may try acquiring the system lock, but weird things may happen.
	// The best solution is probably not acquiring any lock at all, but still...
	// This applies to all other callback functions below.
	ACQUIRE_READ_LOCK(g_PushLock);
	pEntryHead = pProcessType->CallbackList.Flink;
	while (1) {
		pCallbackEntry = CONTAINING_RECORD(pProcessType->CallbackList.Flink, OB_CALLBACK_ENTRY, CallbackList);
		if (pCallbackEntry) {
			ulNumberOfRoutines++;
		}
		if (pCallbackEntry == pEntryHead) {
			break;
		}
	}

	pEntryHead = pThreadType->CallbackList.Flink;
	while (1) {
		pCallbackEntry = CONTAINING_RECORD(pThreadType->CallbackList.Flink, OB_CALLBACK_ENTRY, CallbackList);
		if (pCallbackEntry) {
			ulNumberOfRoutines++;
		}
		if (pCallbackEntry == pEntryHead) {
			break;
		}
	}

	pEntryHead = pExDesktopType->CallbackList.Flink;
	while (1) {
		pCallbackEntry = CONTAINING_RECORD(pExDesktopType->CallbackList.Flink, OB_CALLBACK_ENTRY, CallbackList);
		if (pCallbackEntry) {
			ulNumberOfRoutines++;
		}
		if (pCallbackEntry == pEntryHead) {
			break;
		}
	}

	if (!ulNumberOfRoutines) {
		status = STATUS_NO_CALLBACK_ACTIVE;
		goto Exit;
	}

	if (ulObjectListEntriesInfoLength < (
		(sizeof(ROUTINE_INFORMATION) * ulNumberOfRoutines) + 
		FIELD_OFFSET(KBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION, RoutineInformation))
		) {
		*ulReturnLength = (sizeof(ROUTINE_INFORMATION) * ulNumberOfRoutines) +
			FIELD_OFFSET(KBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION, RoutineInformation);
		status = STATUS_INFO_LENGTH_MISMATCH;
		goto Exit;
	}

	if (!pObjectListEntriesInfo) {
		status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}


	// Retrieving all loaded modules
	status = Kblaster_assist_GetLoadedModulesFillBuffer(&pAllModulesInformation);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}

	pObjectListEntriesInfo->NumberOfRoutines = ulNumberOfRoutines;
	pObjectListEntriesInfo->pArray = 0; // not applicable

	// Reading Process object callbacks
	pEntryHead = pProcessType->CallbackList.Flink;
	while (1) {
		pCallbackEntry = CONTAINING_RECORD(pProcessType->CallbackList.Flink, OB_CALLBACK_ENTRY, CallbackList);
		if (pCallbackEntry) {
			pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.Type = ProcessType;
			pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.CallbackEntry = pCallbackEntry;
			pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.Enabled = pCallbackEntry->Enabled;
			pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.Operation = pCallbackEntry->Operations;
			pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.PreOperation = pCallbackEntry->PreOperation;
			pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.PostOperation = pCallbackEntry->PostOperation;
			Kblaster_p_callback_GetNotifyRoutineModuleInformation(
				&pAllModulesInformation,
				pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.PreOperation,
				&pObjectListEntriesInfo->RoutineInformation[ulIterator].FirstModuleInformation
			);
			Kblaster_p_callback_GetNotifyRoutineModuleInformation(
				&pAllModulesInformation,
				pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.PostOperation,
				&pObjectListEntriesInfo->RoutineInformation[ulIterator].SecondModuleInformation
			);
			ulIterator++;
		}
		
		if (pCallbackEntry == pEntryHead) {
			break;
		}
	}

	// Reading Thread object callbacks
	pEntryHead = pThreadType->CallbackList.Flink;
	while (1) {
		pCallbackEntry = CONTAINING_RECORD(pThreadType->CallbackList.Flink, OB_CALLBACK_ENTRY, CallbackList);
		if (pCallbackEntry) {
			pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.Type = ThreadType;
			pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.CallbackEntry = pCallbackEntry;
			pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.Enabled = pCallbackEntry->Enabled;
			pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.Operation = pCallbackEntry->Operations;
			pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.PreOperation = pCallbackEntry->PreOperation;
			pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.PostOperation = pCallbackEntry->PostOperation;
			Kblaster_p_callback_GetNotifyRoutineModuleInformation(
				&pAllModulesInformation,
				pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.PreOperation,
				&pObjectListEntriesInfo->RoutineInformation[ulIterator].FirstModuleInformation
			);
			Kblaster_p_callback_GetNotifyRoutineModuleInformation(
				&pAllModulesInformation,
				pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.PostOperation,
				&pObjectListEntriesInfo->RoutineInformation[ulIterator].SecondModuleInformation
			);
			ulIterator++;
		}

		if (pCallbackEntry == pEntryHead) {
			break;
		}
	}

	// Reading Desktop object callbacks
	pEntryHead = pExDesktopType->CallbackList.Flink;
	while (1) {
		pCallbackEntry = CONTAINING_RECORD(pExDesktopType->CallbackList.Flink, OB_CALLBACK_ENTRY, CallbackList);
		if (pCallbackEntry) {
			pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.Type = DesktopType;
			pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.CallbackEntry = pCallbackEntry;
			pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.Enabled = pCallbackEntry->Enabled;
			pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.Operation = pCallbackEntry->Operations;
			pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.PreOperation = pCallbackEntry->PreOperation;
			pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.PostOperation = pCallbackEntry->PostOperation;
			Kblaster_p_callback_GetNotifyRoutineModuleInformation(
				&pAllModulesInformation,
				pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.PreOperation,
				&pObjectListEntriesInfo->RoutineInformation[ulIterator].FirstModuleInformation
			);
			Kblaster_p_callback_GetNotifyRoutineModuleInformation(
				&pAllModulesInformation,
				pObjectListEntriesInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.PostOperation,
				&pObjectListEntriesInfo->RoutineInformation[ulIterator].SecondModuleInformation
			);
			ulIterator++;
		}

		if (pCallbackEntry == pEntryHead) {
			break;
		}
	}

Exit:
	RELEASE_READ_LOCK(g_PushLock);
	if (pAllModulesInformation.NumberOfModules &&
		pAllModulesInformation.AllModulesInformation) {
		Kblaster_assist_GetLoadedModulesFreeBuffer(&pAllModulesInformation);
	}

	ulNumberOfRoutines = 0;
	ulIterator = 0;

	return status;
}


__declspec(code_seg("PAGE"))
static
NTSTATUS Kblaster_p_callback_GetRegistryCallbackListEntryInformation(
	_In_ PVOID pRegistryListHead,
	_Inout_opt_ PKBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION pRegistryListEntryInfo,
	_In_ ULONG ulRegistryListEntryInfoLength,
	_Out_ PULONG ulReturnLength)
{
	PAGED_CODE();

	NTSTATUS status = 1;
	KBLR_ASSIST_MODULE_EXTENDED_INFORMATION pAllModulesInformation = { 0 };
	PCMREG_CALLBACK pCallbackEntry = 0;
	ULONG ulNumberOfRoutines = 0;
	ULONG ulIterator = 0;

	if (!pRegistryListHead) {
		status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}

	pCallbackEntry = static_cast<PCMREG_CALLBACK>(pRegistryListHead);

	ACQUIRE_READ_LOCK(g_PushLock);
	while (1) {

		if (pCallbackEntry->Function) {
			ulNumberOfRoutines++;
		}
		pCallbackEntry = CONTAINING_RECORD(pCallbackEntry->List.Flink, CMREG_CALLBACK, List);

		if (pCallbackEntry == pRegistryListHead) {
			break;
		}
	}

	if (!ulNumberOfRoutines) {
		status = STATUS_NO_CALLBACK_ACTIVE;
		goto Exit;
	}

	*ulReturnLength = (ulNumberOfRoutines * sizeof(ROUTINE_INFORMATION)) + 
		FIELD_OFFSET(KBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION, RoutineInformation);

	if (ulRegistryListEntryInfoLength <
		(ulNumberOfRoutines * sizeof(ROUTINE_INFORMATION) +
			FIELD_OFFSET(KBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION, RoutineInformation))
		) {
		status = STATUS_INFO_LENGTH_MISMATCH;
		goto Exit;
	}

	if (!pRegistryListEntryInfo) {
		status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}

	// Retrieving all loaded modules
	status = Kblaster_assist_GetLoadedModulesFillBuffer(&pAllModulesInformation);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}

	pRegistryListEntryInfo->NumberOfRoutines = ulNumberOfRoutines;
	pRegistryListEntryInfo->pArray = pRegistryListHead;

	while (1) {
		if (pCallbackEntry->Function) {
			pRegistryListEntryInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.RegistryCallback.Cookie.QuadPart = pCallbackEntry->Cookie.QuadPart;
			pRegistryListEntryInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.RegistryCallback.Routine = pCallbackEntry->Function;
			Kblaster_p_callback_GetNotifyRoutineModuleInformation(
				&pAllModulesInformation,
				pCallbackEntry->Function,
				&pRegistryListEntryInfo->RoutineInformation[ulIterator].FirstModuleInformation
			);
			ulIterator++;
		}
		pCallbackEntry = CONTAINING_RECORD(pCallbackEntry->List.Flink, CMREG_CALLBACK, List);

		if (pCallbackEntry == pRegistryListHead) {
			break;
		}
	}


Exit:
	RELEASE_READ_LOCK(g_PushLock);
	if (pAllModulesInformation.NumberOfModules &&
		pAllModulesInformation.AllModulesInformation) {
		Kblaster_assist_GetLoadedModulesFreeBuffer(&pAllModulesInformation);
	}

	ulNumberOfRoutines = 0;
	ulIterator = 0;

	return status;
}


// This function enumerates notification routines
// process, thread, image
__declspec(code_seg("PAGE"))
static
NTSTATUS Kblaster_p_callback_GetNotifyRoutineArrayInformation(
	_In_ PVOID pNotifyCallbackArray,
	_Inout_opt_ PKBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION pNotifyCallbackArrayInfo,
	_In_ ULONG ulNotifyCallbackArrayInfoLength,
	_Out_ PULONG ulReturnLength)
{
	PAGED_CODE();


	NTSTATUS status = 1;

	KBLR_ASSIST_MODULE_EXTENDED_INFORMATION pAllModulesInformation = { 0 };
	ULONG NumberOfRoutines = 0;

	ULONG_PTR ulpNotifyRoutine = 0;
	ULONG ulArrayDepth = 45;
	ULONG ulIterator = 0;
	ULONG  ulInserted = 0;


	// Enumerate routines in the callback array.
	ACQUIRE_READ_LOCK(g_Locked);
	for (ulIterator = 0; ulIterator < sizeof(ULONG_PTR) * ulArrayDepth; ulIterator += sizeof(ULONG_PTR)) {
		ulpNotifyRoutine = *(PULONG_PTR)Add2Ptr(pNotifyCallbackArray, ulIterator);

		if (ulpNotifyRoutine) {
			NumberOfRoutines++;
		}
	}

	ulIterator = 0;
	ulpNotifyRoutine = 0;

	// Returning an error status code
	// if no callback are found... very
	// unlikely
	if (!NumberOfRoutines) {
		status = STATUS_NO_CALLBACK_ACTIVE;
		goto Exit;
	}

	// Populating the return length parameter and
	// returning it to the caller along with an error status
	// code if the length of the input buffer (ulNotifyCallbackArrayInfoLength)
	// is not sufficient
	*ulReturnLength = (NumberOfRoutines * sizeof(ROUTINE_INFORMATION)) + 
		FIELD_OFFSET(KBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION, RoutineInformation);

	if (ulNotifyCallbackArrayInfoLength <
		((NumberOfRoutines * sizeof(ROUTINE_INFORMATION)) +
			FIELD_OFFSET(KBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION, RoutineInformation))
		) {
		status = STATUS_INFO_LENGTH_MISMATCH;
		goto Exit;
	}

	if (!pNotifyCallbackArrayInfo) {
		status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}

	// Retrieving all loaded modules
	status = Kblaster_assist_GetLoadedModulesFillBuffer(&pAllModulesInformation);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}

	pNotifyCallbackArrayInfo->pArray = pNotifyCallbackArray;
	pNotifyCallbackArrayInfo->NumberOfRoutines = NumberOfRoutines;

	// Iterating through the callback array again and
	// populate the input buffer with all information
	// including the module the callback belongs to.
	for (ulIterator = 0; ulIterator < (ulArrayDepth * sizeof(ULONG_PTR)); ulIterator += sizeof(ULONG_PTR)) {
		if (ulInserted == NumberOfRoutines) {
			status = STATUS_SUCCESS;
			break;
		}

		ulpNotifyRoutine = *(PULONG_PTR)Add2Ptr(pNotifyCallbackArray, ulIterator);
		if (ulpNotifyRoutine) {
			pNotifyCallbackArrayInfo->RoutineInformation[ulInserted].SpecificRoutineInformation.NotifyRoutine.Handle = ulpNotifyRoutine;
			pNotifyCallbackArrayInfo->RoutineInformation[ulInserted].SpecificRoutineInformation.NotifyRoutine.PointerToHandle = Add2Ptr(pNotifyCallbackArray, ulIterator);
			pNotifyCallbackArrayInfo->RoutineInformation[ulInserted].SpecificRoutineInformation.NotifyRoutine.Routine = INVERT_ROUTINE_HANDLE(ulpNotifyRoutine);
			Kblaster_p_callback_GetNotifyRoutineModuleInformation(
				&pAllModulesInformation,
				INVERT_ROUTINE_HANDLE(ulpNotifyRoutine),
				&pNotifyCallbackArrayInfo->RoutineInformation[ulInserted].FirstModuleInformation
			);
			ulInserted++;
		}
	}


Exit:
	RELEASE_READ_LOCK(g_Locked);
	if (pAllModulesInformation.NumberOfModules &&
		pAllModulesInformation.AllModulesInformation) {
		Kblaster_assist_GetLoadedModulesFreeBuffer(&pAllModulesInformation);
	}

	NumberOfRoutines = 0;
	ulpNotifyRoutine = 0;
	ulIterator = 0;

	return status;
}


__declspec(code_seg("PAGE"))
NTSTATUS Kblaster_callback_RemoveRoutine(
	_In_ PVOID SystemBuffer, 
	_In_ ULONG InputBufferLength)
{
	PAGED_CODE();

	NTSTATUS status = 1;
	PKBLR_CALLBACK_OPERATION pRequest = static_cast<PKBLR_CALLBACK_OPERATION>(SystemBuffer);
	PVOID pCallbackEntryPoint = 0;
	PKBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION pCallbackFullInfo = 0;
	LARGE_INTEGER Cookie = { 0 };
	ULONG ulReturnLength = 0;
	ULONG ulIterator = 0;


	if (InputBufferLength < sizeof(KBLR_CALLBACK_OPERATION)) {
		status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}

	if ((pRequest->CallbackType == ProcessNotify) ||
		(pRequest->CallbackType == ThreadNotify) ||
		(pRequest->CallbackType == ImageNotify) ||
		(pRequest->CallbackType == RegistryCallback)
		) {
		status = KBlaster_p_callback_GetCallbackEntryPoint(pRequest->CallbackType, &pCallbackEntryPoint);
		if (!pCallbackEntryPoint) {
			status = STATUS_UNSUCCESSFUL;
			goto Exit;
		}
	}

	switch (pRequest->CallbackType)
	{
	case ProcessNotify:
	case ThreadNotify:
	case ImageNotify:
		status = Kblaster_p_callback_GetNotifyRoutineArrayInformation(pCallbackEntryPoint, NULL, 0, &ulReturnLength);
		if (!ulReturnLength) {
			goto Exit;
		}

		pCallbackFullInfo = static_cast<PKBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION>(ExAllocatePool2(POOL_FLAG_PAGED, ulReturnLength, POOL_TAG));
		if (!pCallbackFullInfo) {
			status = STATUS_NO_MEMORY;
			goto Exit;
		}

		status = Kblaster_p_callback_GetNotifyRoutineArrayInformation(pCallbackEntryPoint, pCallbackFullInfo, ulReturnLength, &ulReturnLength);
		if (!NT_SUCCESS(status)) {
			goto Exit;
		}

		ACQUIRE_WRITE_LOCK(g_Locked);
		for (ulIterator = 0; ulIterator < pCallbackFullInfo->NumberOfRoutines; ulIterator++) {
			if (pCallbackFullInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.NotifyRoutine.Handle == pRequest->NotifyRoutine.RoutineIdentifier) {
				*(PVOID*)pCallbackFullInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.NotifyRoutine.PointerToHandle = 0;
				status = STATUS_SUCCESS;
				break;
			}
		}
		RELEASE_WRITE_LOCK(g_Locked);

		if (!NT_SUCCESS(status)) {
			status = STATUS_UNSUCCESSFUL;
			goto Exit;
		}

		break;

	case RegistryCallback:
		status = Kblaster_p_callback_GetRegistryCallbackListEntryInformation(pCallbackEntryPoint, NULL, 0, &ulReturnLength);
		if (!ulReturnLength) {
			goto Exit;
		}

		pCallbackFullInfo = static_cast<PKBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION>(ExAllocatePool2(POOL_FLAG_PAGED, ulReturnLength, POOL_TAG));
		if (!pCallbackFullInfo) {
			status = STATUS_NO_MEMORY;
			goto Exit;
		}

		status = Kblaster_p_callback_GetRegistryCallbackListEntryInformation(pCallbackEntryPoint, pCallbackFullInfo, ulReturnLength, &ulReturnLength);
		if (!NT_SUCCESS(status)) {
			goto Exit;
		}

		ACQUIRE_WRITE_LOCK(g_PushLock);
		for (ulIterator = 0; ulIterator < pCallbackFullInfo->NumberOfRoutines; ulIterator++) {
			if (pCallbackFullInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.RegistryCallback.Cookie.QuadPart == pRequest->RegistryCallback.Cookie.QuadPart) {
				Cookie = pCallbackFullInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.RegistryCallback.Cookie;
				status = CmUnRegisterCallback(Cookie);
				break;
			}
		}
		RELEASE_WRITE_LOCK(g_PushLock);

		break;

	case ObjectCallbacks:
		status = Kblaster_p_callback_GetObjectCallbacksEntriesInfo(NULL, 0, &ulReturnLength);
		if (!ulReturnLength) {
			goto Exit;
		}

		pCallbackFullInfo = static_cast<PKBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION>(ExAllocatePool2(POOL_FLAG_PAGED, ulReturnLength, POOL_TAG));
		if (!pCallbackFullInfo) {
			status = STATUS_NO_MEMORY;
			goto Exit;
		}

		status = Kblaster_p_callback_GetObjectCallbacksEntriesInfo(pCallbackFullInfo, ulReturnLength, &ulReturnLength);
		if (!NT_SUCCESS(status)) {
			goto Exit;
		}

		ACQUIRE_WRITE_LOCK(g_PushLock);
		for (ulIterator = 0; ulIterator < pCallbackFullInfo->NumberOfRoutines; ulIterator++) {
			if (pCallbackFullInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.CallbackEntry == pRequest->ObjectCallback.CallbackEntry) {
				*(PULONG)Add2Ptr(pCallbackFullInfo->RoutineInformation[ulIterator].SpecificRoutineInformation.ObjectCallback.CallbackEntry, FIELD_OFFSET(OB_CALLBACK_ENTRY, Enabled)) = 0;
				status = STATUS_SUCCESS;
				break;
			}
		}
		RELEASE_WRITE_LOCK(g_PushLock);

		break;

	default:
		status = STATUS_INVALID_PARAMETER;
		break;
	}

Exit:
	if (pCallbackFullInfo) {
		ExFreePoolWithTag(pCallbackFullInfo, POOL_TAG);
		pCallbackFullInfo = 0;
	}

	return status;

}


__declspec(code_seg("PAGE"))
NTSTATUS Kblaster_callback_EnumerateRoutines(
	_Inout_ PVOID SystemBuffer, 
	_In_ ULONG InputBufferLength, 
	_In_ ULONG OutputBufferLength)
{
	PAGED_CODE();

	NTSTATUS status = 1;
	PKBLR_CALLBACK_OPERATION pRequest = static_cast<PKBLR_CALLBACK_OPERATION>(SystemBuffer);
	PVOID pCallbackEntryPoint = nullptr;
	PKBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION pCallbackFullInfo = 0;
	ULONG ulReturnLength = 0;


	if (InputBufferLength < sizeof(KBLR_CALLBACK_OPERATION)) {
		status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}

	if ((pRequest->CallbackType == ProcessNotify) ||
		(pRequest->CallbackType == ThreadNotify) ||
		(pRequest->CallbackType == ImageNotify) ||
		(pRequest->CallbackType == RegistryCallback)
		) {
		status = KBlaster_p_callback_GetCallbackEntryPoint(pRequest->CallbackType, &pCallbackEntryPoint);
		if (!pCallbackEntryPoint) {
			status = STATUS_UNSUCCESSFUL;
			goto Exit;
		}
	}

	switch (pRequest->CallbackType)
	{
	case ProcessNotify:
	case ThreadNotify:
	case ImageNotify:
		status = Kblaster_p_callback_GetNotifyRoutineArrayInformation(pCallbackEntryPoint, NULL, 0, &ulReturnLength);
		if (!ulReturnLength) {
			goto Exit;
		}

		if (OutputBufferLength < ulReturnLength) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto Exit;
		}
		
		pCallbackFullInfo = static_cast<PKBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION>(ExAllocatePool2(POOL_FLAG_PAGED, ulReturnLength, POOL_TAG));
		if (!pCallbackFullInfo) {
			status = STATUS_NO_MEMORY;
			goto Exit;
		}

		status = Kblaster_p_callback_GetNotifyRoutineArrayInformation(pCallbackEntryPoint, pCallbackFullInfo, ulReturnLength, &ulReturnLength);
		if (!NT_SUCCESS(status)) {
			goto Exit;
		}

		break;

	case RegistryCallback:
		status = Kblaster_p_callback_GetRegistryCallbackListEntryInformation(pCallbackEntryPoint, NULL, 0, &ulReturnLength);
		if (!ulReturnLength) {
			goto Exit;
		}

		if (OutputBufferLength < ulReturnLength) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto Exit;
		}

		pCallbackFullInfo = static_cast<PKBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION>(ExAllocatePool2(POOL_FLAG_PAGED, ulReturnLength, POOL_TAG));
		if (!pCallbackFullInfo) {
			status = STATUS_NO_MEMORY;
			goto Exit;
		}

		status = Kblaster_p_callback_GetRegistryCallbackListEntryInformation(pCallbackEntryPoint, pCallbackFullInfo, ulReturnLength, &ulReturnLength);
		if (!NT_SUCCESS(status)) {
			goto Exit;
		}

		break;

	case ObjectCallbacks:
		status = Kblaster_p_callback_GetObjectCallbacksEntriesInfo(NULL, 0, &ulReturnLength);
		if (!ulReturnLength) {
			goto Exit;
		}

		if (OutputBufferLength < ulReturnLength) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto Exit;
		}

		pCallbackFullInfo = static_cast<PKBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION>(ExAllocatePool2(POOL_FLAG_PAGED, ulReturnLength, POOL_TAG));
		if (!pCallbackFullInfo) {
			status = STATUS_NO_MEMORY;
			goto Exit;
		}

		status = Kblaster_p_callback_GetObjectCallbacksEntriesInfo(pCallbackFullInfo, ulReturnLength, &ulReturnLength);
		if (!NT_SUCCESS(status)) {
			goto Exit;
		}

		break;

	case FilterCallback:
	case NetworkCallback:
		status = STATUS_NOT_IMPLEMENTED;
		break;

	default:
		status = STATUS_INVALID_PARAMETER;
		break;
	}

	if (OutputBufferLength < ulReturnLength) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	RtlCopyMemory(SystemBuffer, pCallbackFullInfo, ulReturnLength);

	status = STATUS_SUCCESS;


Exit:
	if (pCallbackFullInfo) {
		ExFreePoolWithTag(pCallbackFullInfo, POOL_TAG);
		pCallbackFullInfo = 0;
	}

	return status;
}
