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
	case KBLAST_IOCTL_BUG_CHECK:
		KeBugCheck(MANUALLY_INITIATED_CRASH);
		break;

	case KBLAST_IOCTL_PROTECT_WINTCB:
		status = KBlaster_k_ProcessProtection(pUserlandGenericParams->integer1, PROTECTION_WINTCB);
		break;

	case KBLAST_IOCTL_PROTECT_LSA:
		status = KBlaster_k_ProcessProtection(pUserlandGenericParams->integer1, PROTECTION_LSA);
		break;

	case KBLAST_IOCTL_PROTECT_ANTIMALWARE:
		status = KBlaster_k_ProcessProtection(pUserlandGenericParams->integer1, PROTECTION_ANTIMALWARE);
		break;

	case KBLAST_IOCTL_PROTECT_NONE:
		status = KBlaster_k_ProcessProtection(pUserlandGenericParams->integer1, PROTECTION_NONE);
		break;

	case KBLAST_IOCTL_TOKEN_PRIVILEGES_ENABLEALL:
		status = KBlaster_k_TokenPrivilegeManipulate(pUserlandGenericParams->integer1, PRIVILEGES_ENABLEALL);
		break;

	case KBLAST_IOCTL_TOKEN_PRIVILEGES_DISABLEALL:
		status = KBlaster_k_TokenPrivilegeManipulate(pUserlandGenericParams->integer1, PRIVILEGES_DISABLEALL);
		break;

	case KBLAST_IOCTL_TOKEN_STEAL:
		status = KBlaster_k_TokenContextSteal(pUserlandGenericParams->integer1, pUserlandGenericParams->integer2);
		break;

	case KBLAST_IOCTL_TOKEN_RESTORE:
		status = KBlaster_k_TokenContextRestore(pUserlandGenericParams->integer1);
		break;

	case KBLAST_IOCTL_CALLBACK_PROCESS_LIST:
		status = KBlaster_k_EnumProcessCallbacks(outLength, ARRAY_PROCESS, pIRP->UserBuffer);
		break;

	case KBLAST_IOCTL_CALLBACK_THREAD_LIST:
		status = KBlaster_k_EnumProcessCallbacks(outLength, ARRAY_THREAD, pIRP->UserBuffer);
		break;

	case KBLAST_IOCTL_CALLBACK_IMAGE_LIST:
		status = KBlaster_k_EnumProcessCallbacks(outLength, ARRAY_IMAGE, pIRP->UserBuffer);
		break;

	case KBLAST_IOCTL_CALLBACK_REGISTRY_LIST:
		status = KBlaster_k_EnumProcessCallbacks(outLength, LISTENTRY_REGISTRY, pIRP->UserBuffer);
		break;

	case KBLAST_IOCTL_MEMORY_WRITE:
		status = KBlaser_k_memory_manage(pUserlandMemoryParams, NULL, MEMORY_WRITE);
		break;

	case KBLAST_IOCTL_MEMORY_READ:
		status = KBlaser_k_memory_manage(pUserlandMemoryParams, pIRP->UserBuffer, MEMORY_READ);
		break;

		// test IOCTL
	case KBLAST_IOCTL_TEST:
		DbgPrint("[i] WARNING: THIS IS A TEST IOCTL\n");
		//pUserlandGenericParams = (PKBLAST_BUFFER)stack->Parameters.DeviceIoControl.Type3InputBuffer;
		//DbgPrint("[i] Userland parameter: %d\n", pUserlandGenericParams->integer1);

		break;


	default:
		DbgPrint("[-] IOCTL code not found.\n");
		break;
	}

	length = outLength;
	pIRP->IoStatus.Information = length;
	pIRP->IoStatus.Status = status;
	IoCompleteRequest(pIRP, IO_NO_INCREMENT);

	return STATUS_SUCCESS;

}


NTSTATUS CreateClose(PDEVICE_OBJECT pDeviceObject, PIRP pIRP)
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



void DriverCleanup(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("[+] Unloading...\n");
	IoDeleteDevice(DriverObject->DeviceObject);
	IoDeleteSymbolicLink(&symlink);
}




NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_NOT_SUPPORTED;
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);


	DriverObject->DriverUnload = DriverCleanup;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
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
					DbgPrint("[+] Driver loaded.\n");
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

/*
		if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(OutputBuffer))
		{
			DbgPrint("buffer is too small\n");
			break;
		}


		OutputBuffer->integer1 = pUserlandParams->integer1;
		length = sizeof(pUserlandParams->integer1);
*/