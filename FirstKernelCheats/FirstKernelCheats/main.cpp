#include "hook.h"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING reg_path)
{
	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(reg_path);

	DbgPrintEx(0,0,"[JCcheats]Hoyay Driver Entry of mapped driver\n");

	nullhook::call_kernel_function(&nullhook::hook_handler);

	return STATUS_SUCCESS;


}