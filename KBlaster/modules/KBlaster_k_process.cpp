/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlaster_k_process.hpp"


__declspec(code_seg("PAGE"))
NTSTATUS Kblaster_process_TerminateProcess(
	_In_ PVOID pTerminationRequest, 
	_In_ ULONG RequestLength)
{
	NTSTATUS status = 1;
	HANDLE hkProcess = 0;
	OBJECT_ATTRIBUTES objAttr = { 0 };
	CLIENT_ID clientId = { 0 };
	PKBLR_TERM_REQUEST pRequest = static_cast<PKBLR_TERM_REQUEST>(pTerminationRequest);

	if (RequestLength < sizeof(KBLR_TERM_REQUEST) || 
		!pRequest->processId) {
		status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}
	
	InitializeObjectAttributes(
		&objAttr, 
		NULL, 
		OBJ_KERNEL_HANDLE, 
		NULL, 
		NULL);
	clientId.UniqueProcess = UlongToHandle(pRequest->processId);
	clientId.UniqueThread = NULL;
	
	status = ZwOpenProcess(
		&hkProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}

	status = ZwTerminateProcess(
		hkProcess, STATUS_ACCESS_DENIED);

Exit:
	if (hkProcess) {
		ZwClose(hkProcess);
	}

	return status;

}
