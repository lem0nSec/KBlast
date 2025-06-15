/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlaster_k_memory.hpp"


__declspec(code_seg("PAGE"))
NTSTATUS Kblaster_memory_CopyMemory(
	_Inout_ PVOID pMemoryRequest, 
	_In_ ULONG RequestLength)
{
	PAGED_CODE();

	NTSTATUS status = 1;
	MM_COPY_ADDRESS mmCAddress = { 0 };
	SIZE_T NumOfBytesTransferred = 0;
	PMDL pMdl = 0;
	PKBLR_MEMORY_BUFFER pRequest = static_cast<PKBLR_MEMORY_BUFFER>(pMemoryRequest);

	if (RequestLength < sizeof(KBLR_MEMORY_BUFFER)) {
		status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}

	pMdl = IoAllocateMdl(pRequest->ptr, pRequest->size, FALSE, FALSE, NULL);
	if (!pMdl) {
		status = STATUS_UNSUCCESSFUL;
		goto Exit;
	}

	__try {
		
		ACQUIRE_WRITE_LOCK(g_Locked);
		MmProbeAndLockPages(pMdl, KernelMode, pRequest->Operation);
		
		if (pRequest->Operation == IoWriteAccess) {
			mmCAddress.VirtualAddress = pRequest->buffer;
			status = MmCopyMemory(pRequest->ptr, mmCAddress, pRequest->size, MM_COPY_MEMORY_VIRTUAL, &NumOfBytesTransferred);
		}
		else {
			mmCAddress.VirtualAddress = pRequest->ptr;
			status = MmCopyMemory(pRequest->buffer, mmCAddress, pRequest->size, MM_COPY_MEMORY_VIRTUAL, &NumOfBytesTransferred);
		}

		MmUnlockPages(pMdl);
		RELEASE_WRITE_LOCK(g_Locked);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		
		status = GetExceptionCode();
	}

Exit:
	if (pMdl) {
		IoFreeMdl(pMdl);
	}

	return status;
}
