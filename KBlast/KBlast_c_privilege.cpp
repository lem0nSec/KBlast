/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlast.exe ( client )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlast_c_privilege.hpp"



BOOL KBlast_c_CheckTokenIntegrity()
{
	BOOL status = FALSE;
	HANDLE hProcess = 0, hToken = 0;
	PTOKEN_MANDATORY_LABEL pTokenIntegrity = NULL;
	DWORD dwIntegrityLevel = 0, len = 0;
	UCHAR sidSubAuthCount = 0;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
	if (hToken != 0)
	{
		GetTokenInformation(hToken, TokenIntegrityLevel, NULL, NULL, &len);
		pTokenIntegrity = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, (SIZE_T)len);
		if (pTokenIntegrity != 0)
		{
			if (GetTokenInformation(hToken, TokenIntegrityLevel, (LPVOID)pTokenIntegrity, len, &len))
			{
				sidSubAuthCount = *GetSidSubAuthorityCount(pTokenIntegrity->Label.Sid);
				if (GetLastError() == 0)
				{
					dwIntegrityLevel = *GetSidSubAuthority(pTokenIntegrity->Label.Sid, (DWORD)sidSubAuthCount - 1);
				}

				if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
				{
					status = TRUE;
				}
			}
		}

		CloseHandle(hToken);
		LocalFree(pTokenIntegrity);
	}

	return status;

}

static BOOL KBlast_c_SetPrivilege(HANDLE hToken, LPCWSTR privName, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp = { 0 };
	PRIVILEGE_SET privs = { 0 };
	LUID luid = { 0 };
	BOOL status = FALSE;

	if (!LookupPrivilegeValueW(NULL, privName, &luid))
	{
		return status;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else
	{
		tp.Privileges[0].Attributes = 0;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		return status;
	}

	// test privs
	privs.PrivilegeCount = 1;
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.Privilege[0].Luid = luid;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

	PrivilegeCheck(hToken, &privs, &status);

	return status;
}

BOOL KBlast_c_EnableTokenPrivilege(LPCWSTR privName)
{
	HANDLE currentProcessToken = NULL;
	BOOL status = FALSE;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &currentProcessToken) == TRUE)
	{
		status = KBlast_c_SetPrivilege(currentProcessToken, privName, TRUE);
		CloseHandle(currentProcessToken);
	}

	return status;
}