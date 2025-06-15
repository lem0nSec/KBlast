/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlaster_k_assist.hpp"


EX_PUSH_LOCK g_PushLock = 0;
WindowsVersion g_WindowsVersion = WindowsUnsupported;
BOOLEAN g_Locked = 0;

__declspec(code_seg("PAGE"))
static
WindowsVersion Kblaster_p_assist_GetWindowsVersion()
{
	PAGED_CODE();

	WindowsVersion iVersion = WindowsUnsupported;
	NTSTATUS status = 1;
	RTL_OSVERSIONINFOW RtlOSVersion = { 0 };

	RtlOSVersion.dwOSVersionInfoSize = sizeof(RtlOSVersion);
	status = RtlGetVersion(&RtlOSVersion);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}

	/*
	if (RtlOSVersion.dwMajorVersion != 10) {
		iVersion = WindowsUnsupported;
		goto Exit;
	}
	*/

	switch (RtlOSVersion.dwBuildNumber)
	{
	case 14393:
		iVersion = WindowsRedstone1;
		break;

	case 15063:
		iVersion = WindowsRedstone2;
		break;

	case 16299:
		iVersion = WindowsRedstone3;
		break;

	case 17134:
		iVersion = WindowsRedstone4;
		break;

	case 17763:
		iVersion = WindowsRedstone5;
		break;

	case 18362:
		iVersion = Windows19h1;
		break;

	case 18363:
		iVersion = Windows19h2;
		break;

	case 19041:
		iVersion = Windows20h1;
		break;

	case 19042:
		iVersion = Windows20h2;
		break;

	case 19043:
		iVersion = Windows21h1;
		break;

	case 19044:
		iVersion = Windows21h2;
		break;

	case 19045:
		iVersion = Windows22h2;
		break;

	case 22631:
		iVersion = Windows23h2;
		break;

	default:
		iVersion = WindowsUnsupported;
		break;
	}

Exit:

	return iVersion;

}


__declspec(code_seg("PAGE"))
void Kblaster_assist_GetLoadedModulesFreeBuffer(
	_In_ PKBLR_ASSIST_MODULE_EXTENDED_INFORMATION pAllModules)
{
	PAGED_CODE();

	ExFreePoolWithTag(pAllModules->AllModulesInformation, POOL_TAG);
	pAllModules->AllModulesInformation = 0;
	pAllModules->NumberOfModules = 0;
}


__declspec(code_seg("PAGE"))
NTSTATUS Kblaster_assist_GetLoadedModulesFillBuffer(
	_Inout_ PKBLR_ASSIST_MODULE_EXTENDED_INFORMATION pAllModules)
{
	PAGED_CODE();

	NTSTATUS status = 1;
	ULONG ulBufferSize = 0;


	status = AuxKlibQueryModuleInformation(&ulBufferSize, sizeof(AUX_MODULE_EXTENDED_INFO), nullptr);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}
	else if (!ulBufferSize) {
		status = STATUS_UNSUCCESSFUL;
		goto Exit;
	}
	
	pAllModules->AllModulesInformation = static_cast<PAUX_MODULE_EXTENDED_INFO>(ExAllocatePool2(POOL_FLAG_PAGED, ulBufferSize, POOL_TAG));
	if (!pAllModules->AllModulesInformation) {
		status = STATUS_NO_MEMORY;
		goto Exit;
	}

	pAllModules->NumberOfModules = ulBufferSize / sizeof(AUX_MODULE_EXTENDED_INFO);
	
	status = AuxKlibQueryModuleInformation(&ulBufferSize, sizeof(AUX_MODULE_EXTENDED_INFO), pAllModules->AllModulesInformation);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}

Exit:
	if (!NT_SUCCESS(status) &&
		pAllModules->AllModulesInformation) {
		Kblaster_assist_GetLoadedModulesFreeBuffer(pAllModules);
	}

	return status;
}


__declspec(code_seg("PAGE"))
NTSTATUS Kblaster_assist_Initialize()
{
	PAGED_CODE();

	NTSTATUS status = 1;

	g_WindowsVersion = Kblaster_p_assist_GetWindowsVersion();
	if (!g_WindowsVersion) {
		status = STATUS_NOT_SUPPORTED;
		goto Exit;
	}

	ExInitializePushLock(&g_PushLock);

	status = AuxKlibInitialize();
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}

Exit:
	return status;

}