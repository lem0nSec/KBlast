/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlast_c_service.hpp"

BOOL KBlast_c_ServiceManagement(IN SERVICE_ACTION sAction, IN OPTIONAL LPCWSTR lpBinaryPath, OUT OPTIONAL SERVICE_STATUS_PROCESS* sInfoBuffer)
{
	BOOL status = FALSE;
	DWORD szNeeded = 0;
	SC_HANDLE hSC = 0, hService = 0;
	SERVICE_STATUS sStatus = { 0 };


	hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
	if (hSC != 0)
	{
		switch (sAction)
		{
		case SERVICE_CHECK:
			hService = OpenService(hSC, KBLAST_SRV_NAME, SERVICE_QUERY_STATUS);
			if (hService != 0)
			{
				status = QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (BYTE*)sInfoBuffer, sizeof(SERVICE_STATUS_PROCESS), &szNeeded);
				CloseServiceHandle(hService);
			}
			break;

		case SERVICE_CREATE_AND_LOAD:
			hService = CreateService(hSC, KBLAST_SRV_NAME, KBLAST_SRV_NAME, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, lpBinaryPath, NULL, NULL, NULL, NULL, NULL);
			if (hService != NULL)
			{
				status = StartService(hService, 0, NULL);
				if (status == FALSE)
				{
					DeleteService(hService);
				}
				CloseServiceHandle(hService);
			}
			break;

		case SERVICE_UNLOAD_AND_DELETE:
			hService = OpenService(hSC, KBLAST_SRV_NAME, SERVICE_STOP | DELETE);
			if (hService != NULL)
			{
				status = ControlService(hService, SERVICE_CONTROL_STOP, &sStatus);
				if (status == TRUE)
				{
					status = DeleteService(hService);
				}
				CloseServiceHandle(hService);
			}
			break;

		case SERVICE_BINARY_RUN:
			hService = OpenService(hSC, KBLAST_SRV_NAME, SERVICE_START);
			if (hService != NULL)
			{
				status = StartService(hService, 0, NULL);
				CloseServiceHandle(hService);
			}
			break;

		case SERVICE_BINARY_STOP:
			hService = OpenService(hSC, KBLAST_SRV_NAME, SERVICE_STOP);
			if (hService != NULL)
			{
				status = ControlService(hService, SERVICE_CONTROL_STOP, &sStatus);
				CloseServiceHandle(hService);
			}
			break;

		default:
			break;
		}

		CloseServiceHandle(hSC);
	}

	return status;

}



DWORD KBlast_c_ServiceInitialize(IN OPTIONAL SERVICE_ACTION sAction)
{
	BOOL status = FALSE;
	DWORD dwStatus = 0;
	SERVICE_STATUS_PROCESS sInfoBuffer = { 0 };
	HANDLE hFile = 0;
	wchar_t image[] = KBLAST_DRV_BINARY, lpPath[MAX_PATH];

	GetFullPathName(image, MAX_PATH, lpPath, nullptr);

	hFile = CreateFile(lpPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_FILE_NOT_FOUND)
		{
			dwStatus = KBLAST_BINARY_NOT_FOUND;
		}
		else
		{
			dwStatus = KBLAST_BINARY_ERROR_GENERIC;
		}

		return dwStatus;

	}
	CloseHandle(hFile);


	status = KBlast_c_ServiceManagement(SERVICE_CHECK, (LPCWSTR)lpPath, &sInfoBuffer);
	if ((sAction == NULL) || (sAction == SERVICE_CREATE_AND_LOAD))
	{
		switch (status)
		{
		case FALSE:
			wprintf(L"[+] Registering service...\n");
			status = KBlast_c_ServiceManagement(SERVICE_CREATE_AND_LOAD, (LPCWSTR)lpPath, &sInfoBuffer);
			if (status == TRUE)
			{
				dwStatus = KBLAST_SD_SUCCESS;
			}
			else
			{
				dwStatus = KBLAST_SD_FAILED;
			}
			break;

		case TRUE:
			wprintf(L"[i] Service found.\n");
			if (sInfoBuffer.dwCurrentState != SERVICE_RUNNING)
			{
				status = KBlast_c_ServiceManagement(SERVICE_BINARY_RUN, (LPCWSTR)lpPath, &sInfoBuffer);
				if (status == TRUE)
				{
					dwStatus = KBLAST_D_SUCCESS;
				}
				else
				{
					dwStatus = KBLAST_D_FAILED;
				}
			}
			else
			{
				dwStatus = KBLAST_SD_EXIST;
			}
			break;

		default:
			break;
		}
	}

	if (sAction == SERVICE_UNLOAD_AND_DELETE)
	{
		if (status == TRUE)
		{
			wprintf(L"[+] Cleaning...\n");
			status = KBlast_c_ServiceManagement(SERVICE_UNLOAD_AND_DELETE, (LPCWSTR)lpPath, &sInfoBuffer);
			if (status == TRUE)
			{
				dwStatus = KBLAST_SD_SUCCESS;
			}
			else
			{
				dwStatus = KBLAST_SD_FAILED;
			}
		}
	}


	return dwStatus;

}