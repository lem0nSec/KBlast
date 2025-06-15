/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlaster_k_callbacks.hpp"

/*
PVOID* find()
{
	POBJECT_TYPE pObType = *PsProcessType;
	return (PVOID*)((__int64)pObType + 0xC8);
}
*/

// This function needs major improvements.
// Not having time for now.
// Tested on 19045 to 22631
__declspec(code_seg("PAGE"))
static
NTSTATUS KBlaster_p_callback_GetCallbackStoragePointer(
	_In_ CallbackType cType, 
	_Out_ PVOID * ppStorage)
{
	PAGED_CODE();

	NTSTATUS status = 1;
	ULONG64 pInitialFunction = 0;
	ULONG64 pInnerFunction = 0;
	ULONG64 i, offset = 0;
	UCHAR initialOpcode1 = 0xE8, initialOpcode2 = 0xE9;
	UCHAR innerOpcode1 = 0, innerOpcode2 = 0;
	UNICODE_STRING initialFunctionName = { 0, 0, 0 };

	if (!ppStorage) {
		status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}
	*ppStorage = 0;

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

	case ImageLoad:
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

	case ObjectCallback:
	case FilterCallback:
	case NetworkCallback:
		status = STATUS_NOT_IMPLEMENTED;
		break;

	default:
		break;
	}

	if ((cType == ProcessNotify) ||
		(cType == ThreadNotify) ||
		(cType == ImageLoad)) {
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
						*ppStorage = (PVOID)(i + offset + 7);
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
				*ppStorage = (PVOID)(i + offset + 7);
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
NTSTATUS Kblaster_p_callback_GetCallbackListEntryInformation(
	_In_ PVOID pNotifyCallbackArray,
	_Inout_opt_ PKBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION pNotifyCallbackArrayInfo,
	_In_ ULONG ulNotifyCallbackArrayInfoLength,
	_Out_ PULONG ulReturnLength)
{
	PAGED_CODE();

	NTSTATUS status = 1;
	KBLR_ASSIST_MODULE_EXTENDED_INFORMATION pAllModulesInformation = { 0 };
	PCMREG_CALLBACK pCallbackEntry = 0;
	ULONG ulNumberOfRoutines = 0;
	ULONG ulIterator = 0;

	if (!pNotifyCallbackArray) {
		status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}

	pCallbackEntry = static_cast<PCMREG_CALLBACK>(pNotifyCallbackArray);

	ACQUIRE_READ_LOCK(g_PushLock);
	while (1) {

		if (pCallbackEntry->Function) {
			ulNumberOfRoutines++;
		}
		pCallbackEntry = CONTAINING_RECORD(pCallbackEntry->List.Flink, CMREG_CALLBACK, List);

		if (pCallbackEntry == pNotifyCallbackArray) {
			break;
		}
	}

	if (!ulNumberOfRoutines) {
		status = STATUS_NO_CALLBACK_ACTIVE;
		goto Exit;
	}

	*ulReturnLength = (ulNumberOfRoutines * sizeof(ROUTINE_INFORMATION)) + 
		FIELD_OFFSET(KBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION, RoutineInformation);

	if (ulNotifyCallbackArrayInfoLength <
		(ulNumberOfRoutines * sizeof(ROUTINE_INFORMATION) +
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

	pNotifyCallbackArrayInfo->NumberOfRoutines = ulNumberOfRoutines;
	pNotifyCallbackArrayInfo->pArray = pNotifyCallbackArray;

	while (1) {
		if (pCallbackEntry->Function) {
			pNotifyCallbackArrayInfo->RoutineInformation[ulIterator].Handle = (ULONG_PTR)pCallbackEntry->Cookie.QuadPart;
			pNotifyCallbackArrayInfo->RoutineInformation[ulIterator].Routine = pCallbackEntry->Function;
			Kblaster_p_callback_GetNotifyRoutineModuleInformation(
				&pAllModulesInformation,
				pCallbackEntry->Function,
				&pNotifyCallbackArrayInfo->RoutineInformation[ulIterator].ModuleInformation
			);
			ulIterator++;
		}
		pCallbackEntry = CONTAINING_RECORD(pCallbackEntry->List.Flink, CMREG_CALLBACK, List);

		if (pCallbackEntry == pNotifyCallbackArray) {
			break;
		}
	}


Exit:
	RELEASE_READ_LOCK(g_PushLock);

	return status;
}


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
			pNotifyCallbackArrayInfo->RoutineInformation[ulInserted].Handle = (ULONG_PTR)(ulpNotifyRoutine);
			pNotifyCallbackArrayInfo->RoutineInformation[ulInserted].PointerToHandle = Add2Ptr(pNotifyCallbackArray, ulIterator);
			pNotifyCallbackArrayInfo->RoutineInformation[ulInserted].Routine = INVERT_ROUTINE_HANDLE(ulpNotifyRoutine);
			Kblaster_p_callback_GetNotifyRoutineModuleInformation(
				&pAllModulesInformation,
				INVERT_ROUTINE_HANDLE(ulpNotifyRoutine),
				&pNotifyCallbackArrayInfo->RoutineInformation[ulInserted].ModuleInformation
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
	PKBLR_CALLBACK_REMOVE pRequest = static_cast<PKBLR_CALLBACK_REMOVE>(SystemBuffer);
	PVOID pCallbackArray = 0;
	PKBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION pCallbackFullInfo = 0;
	LARGE_INTEGER RegistryRoutineIdentifier = { 0 };
	ULONG ulReturnLength = 0;
	ULONG ulIterator = 0;


	if (InputBufferLength < sizeof(KBLR_CALLBACK_REMOVE)) {
		status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}

	status = KBlaster_p_callback_GetCallbackStoragePointer(pRequest->CallbackType, &pCallbackArray);
	if (!NT_SUCCESS(status) ||
		!pCallbackArray) {
		status = STATUS_UNSUCCESSFUL;
		goto Exit;
	}

	switch (pRequest->CallbackType)
	{
	case ProcessNotify:
	case ThreadNotify:
	case ImageLoad:
		status = Kblaster_p_callback_GetNotifyRoutineArrayInformation(pCallbackArray, NULL, 0, &ulReturnLength);
		if (!ulReturnLength) {
			goto Exit;
		}

		pCallbackFullInfo = static_cast<PKBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION>(ExAllocatePool2(POOL_FLAG_PAGED, ulReturnLength, POOL_TAG));
		if (!pCallbackFullInfo) {
			status = STATUS_NO_MEMORY;
			goto Exit;
		}

		status = Kblaster_p_callback_GetNotifyRoutineArrayInformation(pCallbackArray, pCallbackFullInfo, ulReturnLength, &ulReturnLength);
		if (!NT_SUCCESS(status)) {
			goto Exit;
		}

		ACQUIRE_WRITE_LOCK(g_Locked);
		for (ulIterator = 0; ulIterator < pCallbackFullInfo->NumberOfRoutines; ulIterator++) {
			if (pCallbackFullInfo->RoutineInformation[ulIterator].Handle == pRequest->RoutineIdentifier) {
				*(PVOID*)pCallbackFullInfo->RoutineInformation[ulIterator].PointerToHandle = 0;
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
		status = Kblaster_p_callback_GetCallbackListEntryInformation(pCallbackArray, NULL, 0, &ulReturnLength);
		if (!ulReturnLength) {
			goto Exit;
		}

		pCallbackFullInfo = static_cast<PKBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION>(ExAllocatePool2(POOL_FLAG_PAGED, ulReturnLength, POOL_TAG));
		if (!pCallbackFullInfo) {
			status = STATUS_NO_MEMORY;
			goto Exit;
		}

		status = Kblaster_p_callback_GetCallbackListEntryInformation(pCallbackArray, pCallbackFullInfo, ulReturnLength, &ulReturnLength);
		if (!NT_SUCCESS(status)) {
			goto Exit;
		}

		ACQUIRE_WRITE_LOCK(g_PushLock);
		for (ulIterator = 0; ulIterator < pCallbackFullInfo->NumberOfRoutines; ulIterator++) {
			if (pCallbackFullInfo->RoutineInformation[ulIterator].Handle == pRequest->RoutineIdentifier) {
				RegistryRoutineIdentifier.QuadPart = (LONGLONG)pCallbackFullInfo->RoutineInformation[ulIterator].Handle;
				status = CmUnRegisterCallback(RegistryRoutineIdentifier);
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
	PKBLR_CALLBACK pRequest = static_cast<PKBLR_CALLBACK>(SystemBuffer);
	PVOID pCallbackArray = nullptr;
	PKBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION pCallbackFullInfo = 0;
	ULONG ulReturnLength = 0;

	if (InputBufferLength < sizeof(KBLR_CALLBACK)) {
		status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}

	status = KBlaster_p_callback_GetCallbackStoragePointer(pRequest->CallbackType, &pCallbackArray);
	if (!NT_SUCCESS(status) ||
		!pCallbackArray) {
		status = STATUS_UNSUCCESSFUL;
		goto Exit;
	}

	switch (pRequest->CallbackType)
	{
	case ProcessNotify:
	case ThreadNotify:
	case ImageLoad:
		status = Kblaster_p_callback_GetNotifyRoutineArrayInformation(pCallbackArray, NULL, 0, &ulReturnLength);
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

		status = Kblaster_p_callback_GetNotifyRoutineArrayInformation(pCallbackArray, pCallbackFullInfo, ulReturnLength, &ulReturnLength);
		if (!NT_SUCCESS(status)) {
			goto Exit;
		}

		break;

	case RegistryCallback:
		status = Kblaster_p_callback_GetCallbackListEntryInformation(pCallbackArray, NULL, 0, &ulReturnLength);
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

		status = Kblaster_p_callback_GetCallbackListEntryInformation(pCallbackArray, pCallbackFullInfo, ulReturnLength, &ulReturnLength);
		if (!NT_SUCCESS(status)) {
			goto Exit;
		}

		break;

	case ObjectCallback:
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
