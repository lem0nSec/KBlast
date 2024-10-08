/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlaster_k_protection.hpp"


NTSTATUS KBlaster_k_ProcessProtection(int processID, PROTECTION_OPTION prOption)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEprocess = 0;
	PPROCESS_PROTECTION_INFO ppInfo = 0;

	if (KBlaster_k_utils_GetWindowsVersion() == WINDOWS_UNSUPPORTED)
	{
		status = STATUS_NOT_SUPPORTED;
		goto exit;
	}

	status = PsLookupProcessByProcessId((HANDLE)processID, &pEprocess);
	if (NT_SUCCESS(status))
	{
		ppInfo = (PPROCESS_PROTECTION_INFO)((ULONG_PTR)pEprocess + EPROCESS_SIGNATURE_LEVEL_OFFSET[KBlaster_k_utils_GetWindowsVersion()]);

		switch (prOption)
		{
		case PROTECTION_WINTCB: // full (wintcb)
			ppInfo->SignatureLevel = 30;
			ppInfo->SectionSignatureLevel = 28;
			ppInfo->Protection.Type = 2;
			ppInfo->Protection.Signer = 6;
			break;

		case PROTECTION_LSA: // light (lsa)
			ppInfo->SignatureLevel = 38;
			ppInfo->SectionSignatureLevel = 8;
			ppInfo->Protection.Type = 1;
			ppInfo->Protection.Signer = 4;
			break;

		case PROTECTION_ANTIMALWARE: // light (antimalware)
			ppInfo->SignatureLevel = 37;
			ppInfo->SectionSignatureLevel = 7;
			ppInfo->Protection.Type = 1;
			ppInfo->Protection.Signer = 3;
			break;

		case PROTECTION_NONE:
			ppInfo->SignatureLevel = 0;
			ppInfo->SectionSignatureLevel = 0;
			ppInfo->Protection.Type = 0;
			ppInfo->Protection.Signer = 0;
			break;

		default:
			break;
		}

		ObDereferenceObject(pEprocess);
	}

exit:

	return status;

}