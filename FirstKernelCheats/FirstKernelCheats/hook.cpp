#include "hook.h"

bool nullhook::call_kernel_function(void* kernel_function_address)
{
	if (!kernel_function_address)
		return false;

	PVOID* function = reinterpret_cast<PVOID*>(get_system_module_export(L"dxgkrnl.sys", "NtDxgkGetTrackedWorkloadStatistics"));

	DbgPrintEx(0, 0, "[JCcheats]after mapping to dxgkrnl with function: %p \n", function);

	if (!function)
	{
		DbgPrintEx(0, 0, "[JCcheats] PVOID* function = reinterpret_cast<PVOID*>(get_system_module_export( function is not valid return false \n");
		return false;
	}
	BYTE orig[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	
	//detected , change here to evade detection by battleeye
	BYTE shell_code[] = { 0x48, 0xB8 }; //mov rax, 
	BYTE shell_code_end[] = { 0xFF, 0xE0 }; //jmp rax(custom function address )

	RtlSecureZeroMemory(&orig, sizeof(orig));

	DbgPrintEx(0, 0, "[JCcheats]RtlSecureZeroMemory(&orig, sizeof(orig)); \n");

	memcpy((PVOID)((ULONG_PTR)orig), &shell_code, sizeof(shell_code));

	uintptr_t hook_address = reinterpret_cast<uintptr_t>(kernel_function_address);
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code)), &hook_address, sizeof(void*));
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code) + sizeof(void*)), &shell_code_end, sizeof(shell_code_end));

	DbgPrintEx(0, 0, "[JCcheats]memcpy function \n");

	write_to_read_only_memory(function, &orig, sizeof(orig));

	DbgPrintEx(0, 0, "[JCcheats]write_to_read_only_memory(function, &orig, sizeof(orig)); \n");

	return true;
}

NTSTATUS nullhook::hook_handler(PVOID called_param)
{	
	//bool pass = (called_param == NULL);
	JCH_Options* instruction = (JCH_Options*)called_param;

	DbgPrintEx(0, 0, "[JCcheats]Debugging nullhook::hook_handler \n");

	if (instruction->req_base != FALSE && instruction->IsProc64bit == TRUE)
	{
		ANSI_STRING AS;
		UNICODE_STRING ModuleName;

		RtlInitAnsiString(&AS, instruction->module_name);
		RtlAnsiStringToUnicodeString(&ModuleName, &AS,TRUE);

		DbgPrintEx(0, 0, "[JCcheats]RtlAnsiStringToUnicodeString(&ModuleName, &AS,TRUE); \n");
		DbgPrintEx(0, 0, "[JCcheats]pid being passed into the function %u \n", instruction->pid);
		PEPROCESS process;
		PsLookupProcessByProcessId((HANDLE)instruction->pid, &process);

		DbgPrintEx(0, 0, "PsLookupProcessByProcessId((HANDLE)instruction->pid, &process); process address: %p \n", (void *)&process);

		PVOID base_address64 = NULL;
		base_address64 = get_module_base_x64(process, ModuleName);
		instruction->base_address = base_address64;
		RtlFreeUnicodeString(&ModuleName);

	}

	if (instruction->req_base != FALSE && instruction->IsProc64bit == FALSE)
	{
		ANSI_STRING AS;
		UNICODE_STRING ModuleName;

		RtlInitAnsiString(&AS, instruction->module_name);
		RtlAnsiStringToUnicodeString(&ModuleName, &AS, TRUE);

		PEPROCESS process;
		PsLookupProcessByProcessId((HANDLE)instruction->pid, &process);

		ULONG base_address32 = NULL;
		base_address32 = get_module_base_x32(process, ModuleName, (HANDLE)instruction->pid);
		instruction->base_address32 = base_address32;
		RtlFreeUnicodeString(&ModuleName);


	}

	if (instruction->write != FALSE && instruction->IsProc64bit == TRUE)
	{
		if (instruction->address < 0x7FFFFFFFFFFF && instruction->address > 0)
		{
			//allocate pool is detected EAC/BE check for the pool and uploads to the serve analyze and bypass this
			PVOID kernelBuff = ExAllocatePool(NonPagedPool, instruction->size);

			if (!kernelBuff)
			{
				return STATUS_UNSUCCESSFUL;

			}

			if (!memcpy(kernelBuff, instruction->buffer_address, instruction->size))
			{
				return STATUS_UNSUCCESSFUL;
			}

			PEPROCESS process;
			PsLookupProcessByProcessId((HANDLE)instruction->pid, &process);
			write_kernel_memory((HANDLE)instruction->pid, instruction->address, kernelBuff, instruction->size);
			ExFreePool(kernelBuff);
		}
	}

	if (instruction->read != FALSE && instruction->IsProc64bit == TRUE)
	{
		if (instruction->address < 0x7FFFFFFFFFFF && instruction->address > 0)
		{
			read_kernel_memory((HANDLE)instruction->pid, instruction->address, instruction->output, instruction->size);
		}
	}

	return STATUS_SUCCESS;
}