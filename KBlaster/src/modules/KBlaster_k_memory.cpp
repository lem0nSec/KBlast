#include "KBlaster_k_memory.hpp"


NTSTATUS KBlaser_k_memory_manage(IN PKBLAST_MEMORY_BUFFER InBuf, OUT OPTIONAL PVOID OutBuf, KBLAST_MEMORY_ACTION action)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	KBLAST_MEMORY_BUFFER* buf = (KBLAST_MEMORY_BUFFER*)OutBuf;
	MM_COPY_ADDRESS mmCAddress = { 0 };
	SIZE_T old = 0;

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

	return status;

}