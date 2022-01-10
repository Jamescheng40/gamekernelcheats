#include "hook.h"

bool nullhook::call_kernel_function(void* kernel_function_address)
{
	if (!kernel_function_address)
		return false;

	PVOID* function = reinterpret_cast<PVOID*>(get_system_module_export("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtQueryCompositionSurfaceStatistics"));

	if (!function)
		return false;

	BYTE orig[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	
	//detected , change here to evade detection by battleeye
	BYTE shell_code[] = { 0x48, 0xB8 }; //mov rax, 
	BYTE shell_code_end[] = { 0xFF, 0xE0 }; //jmp rax(custom function address )

	RtlSecureZeroMemory(&orig, sizeof(orig));

	memcpy((PVOID)((ULONG_PTR)orig), &shell_code, sizeof(shell_code));

	uintptr_t hook_address = reinterpret_cast<uintptr_t>(kernel_function_address);
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code)), &hook_address, sizeof(void*));
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code) + sizeof(void*)), &shell_code_end, sizeof(shell_code_end));

	write_to_read_only_memory(function, &orig, sizeof(orig));

	return true;
}

NTSTATUS nullhook::hook_handler(PVOID called_param)
{	
	//bool pass = (called_param == NULL);
	JCH_Options* instruction = (JCH_Options*)called_param;

	if (instruction->req_base != FALSE && instruction->IsProc64bit == TRUE)
	{
		ANSI_STRING AS;
		UNICODE_STRING ModuleName;

		RtlInitAnsiString(&AS, instruction->module_name);
		RtlAnsiStringToUnicodeString(&ModuleName, &AS,TRUE);

		PEPROCESS process;
		PsLookupProcessByProcessId((HANDLE)instruction->pid, &process);

		ULONG64 base_address64 = NULL;
		base_address64 = get_module_base_x64(process, ModuleName);
		instruction->base_address = base_address64;
		RtlFreeUnicodeString(&ModuleName);

	}

	//if (instruction->req_base != FALSE && instruction->IsProc64bit == FALSE)
	//{
	//	ANSI_STRING AS;
	//	UNICODE_STRING ModuleName;

	//	RtlInitAnsiString(&AS, instruction->module_name);
	//	RtlAnsiStringToUnicodeString(&ModuleName, &AS, TRUE);

	//	PEPROCESS process;
	//	PsLookupProcessByProcessId((HANDLE)instruction->pid, &process);

	//	ULONG base_address32 = NULL;
	//	base_address32 = get_module_base_x32(process, ModuleName, (HANDLE)instruction->pid);
	//	instruction->base_address32 = base_address32;
	//	RtlFreeUnicodeString(&ModuleName);


	//}

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