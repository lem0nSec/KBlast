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

		LocalFree(pTokenIntegrity);
	}

	return status;

}