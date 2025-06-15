/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "Kblast_service.hpp"


SC_HANDLE g_KblasterService = 0;

BOOL Kblast_p_service_CloseServiceObject(
	_In_ SC_HANDLE hSCObject)
{
	if (!hSCObject) {
		return FALSE;
	}

	return CloseServiceHandle(hSCObject);
}

BOOL Kblast_service_RunService(
	_In_ LPCWSTR lpServiceName,
	_In_ LPCWSTR lpBinaryPath,
	_Inout_ LPSC_HANDLE lphService)
{
	BOOL status = FALSE;

	SC_HANDLE hServiceManger = 0;
	SC_HANDLE hService = 0;

	hServiceManger = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
	if (!hServiceManger) {
		goto Exit;
	}

	hService = CreateService(hServiceManger,
		lpServiceName,
		lpServiceName,
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_IGNORE,
		lpBinaryPath,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL);
	if (!hService) {
		if (GetLastError() == ERROR_SERVICE_EXISTS) {
			hService = OpenService(hServiceManger, lpServiceName, SERVICE_ALL_ACCESS);
			if (!hService) {
				goto Exit;
			}
		}
		else {
			goto Exit;
		}
	}

	status = StartService(hService, 0, NULL);

	*lphService = hService;


Exit:
	if (hServiceManger) {
		CloseServiceHandle(hServiceManger);
	}

	return status;
}


BOOL Kblast_service_DeleteService(
	_In_ SC_HANDLE hService)
{
	BOOL status = FALSE;
	SERVICE_STATUS ServiceStatus = { 0 };

	if (!ControlService(hService, SERVICE_CONTROL_STOP, &ServiceStatus)) {
		goto Exit;
	}

	if (!DeleteService(hService)) {
		goto Exit;
	}

	status = CloseServiceHandle(hService);

Exit:
	return status;
}
