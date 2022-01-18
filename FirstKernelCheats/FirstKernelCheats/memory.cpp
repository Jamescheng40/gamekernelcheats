#include "memory.h"
#include "utility.h"

PVOID get_system_module_base(const char* module_name)
{
	ULONG bytes = 0;
	//?
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);

	if (!bytes)
		return NULL;

	//?
	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x4E554C4C);

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status))
		return NULL;

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;

	PVOID module_base = 0, module_size = 0;

	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		if (strcmp((char*)module[i].FullPathName, module_name) == 0)
		{
			module_base = module[i].ImageBase;
			module_size = (PVOID)module[i].ImageSize;
			break;
		}
	}

	if (modules)
		ExFreePoolWithTag(modules, NULL);

	if (module_base <= NULL)
		return NULL;
	
	return module_base;
}

//PVOID get_system_module_export(const char* module_name, LPCSTR routine_name)
//{
//	PVOID lpModule = get_system_module_base(module_name);
//
//	if (!lpModule)
//		return NULL;
//
//	return RtlFindExportedRoutineByName(lpModule, routine_name);
//}

PVOID get_system_routine_address(PCWSTR routine_name)
{
	UNICODE_STRING name;
	RtlInitUnicodeString(&name, routine_name);
	//get system routine address get the executable or dll's address; equivalent to usermode getprocaddress
	return MmGetSystemRoutineAddress(&name);

}

PVOID get_system_module_export(PCWSTR module_name, LPCSTR routine_name)
{
	//PVOID lpModule = get_system_module_base(module_name);
	PLIST_ENTRY module_list = reinterpret_cast<PLIST_ENTRY>(get_system_routine_address(L"PsLoadedModuleList"));

	if (!module_list)
	{
		DbgPrintEx(0, 0, "[JCcheats] get_system_module_export module list is NULL \n");
		return NULL;
	}
	for (PLIST_ENTRY link = module_list; link != module_list->Blink; link = link->Flink)
	{
		LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(link,LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
		DbgPrintEx(0, 0, "[JCcheats] entering the loop in the get_system_module_export module \n");
		UNICODE_STRING name;
		RtlInitUnicodeString(&name, module_name);
		if (RtlEqualUnicodeString(&entry->BaseDllName, &name, TRUE))
		{
			DbgPrintEx(0, 0, "[JCcheats] entry is found and outputing the dllBase next \n");
			return (entry->DllBase) ? RtlFindExportedRoutineByName(entry->DllBase, routine_name) : NULL;
		}

	}
	DbgPrintEx(0, 0, "[JCcheats] entry is not found and returning NULL \n");
	return NULL;

}

bool write_memory(void* address, void* buffer, size_t size)
{
	if (!RtlCopyMemory(address, buffer, size))
	{
		return false;
	}
	else
	{
		return true;
	}
}

bool write_to_read_only_memory(void* address, void* buffer, size_t size)
{
	PMDL Mdl = IoAllocateMdl(address, size, FALSE,FALSE,NULL);

	if (!Mdl)
		return false;

	MmProbeAndLockPages(Mdl,KernelMode,IoReadAccess);
	PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

	write_memory(Mapping, buffer, size);
	MmUnmapLockedPages(Mapping, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);

	return true;
}

ULONG get_module_base_x32(PEPROCESS proc, UNICODE_STRING module_name, HANDLE pid)
{


//psuedo code start: for reading physical memory; notice that the readphysicalmemory is a dll function hence it can not be called in the kernel space
	
	//BOOLEAN iswow64 = (PsGetProcessWow64Process(proc) != NULL) ? TRUE : FALSE;

	//if (iswow64 == FALSE)
	//{
	//	return 0;
	//}

	//PVOID peb_address = PsGetProcessWow64Process(proc);

	////parameter for passing to the read process memory
	//NTSTATUS status;
	//PEB32 peb_process = { 0 };
	//SIZE_T s_read = 0;
	//ULONG outdllbase = 0;


	////ReadProcessMemory(pid, (ULONG64)pebPtr, (ULONG64)&peb, sizeof(PEB32));
	//status = ReadProcessMemory(pid, peb_address, &peb_process, sizeof(PEB32), &s_read);

	//if (!NT_SUCCESS(status))
	//	return status;

	//PEB_LDR_DATA32 peb_ldr_data = { 0 };
	//status = ReadProcessMemory(pid, (PVOID)peb_process.LdrData, &peb_ldr_data, sizeof(PEB_LDR_DATA32), &s_read);

	//if (!NT_SUCCESS(status))
	//	return status;

	//LIST_ENTRY32* ldr_list_head = (LIST_ENTRY32*)peb_ldr_data.InLoadOrderModuleList.Flink;
	//LIST_ENTRY32* ldr_current_node = (LIST_ENTRY32*)peb_ldr_data.InLoadOrderModuleList.Flink;

	////PEB_LDR_DATA32 is for dll only according to https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.html. Not sure about exe
	//while (ldr_list_head != ldr_current_node)
	//{
	//	LDR_DATA_TABLE_ENTRY32 lst_entry = { 0 };
	//	status = ReadProcessMemory(pid, (PVOID)ldr_current_node, &lst_entry, sizeof(LDR_DATA_TABLE_ENTRY32), &s_read);
	//	if (!NT_SUCCESS(status))
	//		return status;

	//	ldr_current_node = (LIST_ENTRY32*)lst_entry.InLoadOrderLinks.Flink;
	//	if (lst_entry.BaseDllName.Length > 0)
	//	{
	//		WCHAR sz_base_dll_name[MAX_PATH] = { 0 };
	//		status = ReadProcessMemory(pid, (PVOID)lst_entry.BaseDllName.Buffer, &sz_base_dll_name, lst_entry.BaseDllName.Length, &s_read);

	//		if (!NT_SUCCESS(status))
	//			return status;

	//		if (crt_strcmp(sz_base_dll_name, module_name, true))
	//		{
	//			if (lst_entry.DllBase != 0 && lst_entry.SizeOfImage != 0)
	//			{
	//				outdllbase = (ULONG)lst_entry.DllBase;

	//				break;
	//			}
	//		}
	//	}

	//}
//psuedo code for reading physical memory ends 
	
	BOOLEAN iswow64 = (PsGetProcessWow64Process(proc) != NULL) ? TRUE : FALSE;

	if (iswow64 == FALSE)
	{
		return 0;
	}

	PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(proc);
	KAPC_STATE state;

	KeStackAttachProcess(proc, &state);

	PPEB_LDR_DATA32 pLdr = (PPEB_LDR_DATA32)pPeb32->Ldr;

	if (!pLdr)
	{
		KeUnstackDetachProcess(&state);
		return NULL;

	}

	for (PLIST_ENTRY32 list = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList.Flink; list != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList; list = (PLIST_ENTRY32)list->Flink)
	{
		PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
		
		ULONG unicode32strmodule = pEntry->BaseDllName.Buffer;
		//wchar_t* uni32str1 = reinterpret_cast<wchar_t*>(&unicode32strmodule);

		
		//if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) == NULL)
		//{
		//	ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
		//	KeUnstackDetachProcess(&state);
		//	return baseAddr;

		//}
	}

	KeUnstackDetachProcess(&state);
	//return NULL;

	return 0;
}

PVOID get_module_base_x64(PEPROCESS proc, UNICODE_STRING module_name)
{

	PPEB pPeb = PsGetProcessPeb(proc);


	if (!pPeb)
	{
		DbgPrintEx(0, 0, "[JCcheats]PPEB pPeb = PsGetProcessPeb returned null  \n");
		return NULL;
	}

	KAPC_STATE state;

	DbgPrintEx(0, 0, "[JCcheats]inside get module x64 and .exe base is %p  \n", pPeb->lpImageBaseAddress);
	KeStackAttachProcess(proc, &state);

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->pLdr;
	//ReadProcessMemory(pid, ldrdata.InLoadOrderModuleList.Flink,
	//	(ULONG64)&currEntry, sizeof(LDR_DATA_TABLE_ENTRY32));
	DbgPrintEx(0, 0, "[JCcheats]inside get module x64 and module name is %wZ  \n", &module_name);
	if (!pLdr)
	{
		DbgPrintEx(0, 0, "[JCcheats]PPEB_LDR_DATA pLdr is null \n");
		KeUnstackDetachProcess(&state);
		return NULL;

	}
	int i = 0;
		for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->InMemoryOrderModuleList.Flink; list != &pLdr->InMemoryOrderModuleList; list = (PLIST_ENTRY)list->Flink)
		{
			if (i >= 30)
			{
				break;
			}
			PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
			DbgPrintEx(0, 0, "[JCcheats]inside get module x64 and this particular base dll name is %wZ  \n", &pEntry->BaseDllName);

			DbgPrintEx(0, 0, "[JCcheats]this particular instance address is void* is  %p  \n", (void*)(pEntry->DllBase));

			DbgPrintEx(0, 0, "[JCcheats]this full dll name is %wZ  \n", &pEntry->FullDllName);

			DbgPrintEx(0,0, "[JCcheats]this base dll name in ulong64 is %I64u	 \n", (ULONG64)pEntry->DllBase);

			DbgPrintEx(0, 0, "[JCcheats]this entry point in ulong64 is %I64u	 \n", (ULONG64)pEntry->EntryPoint);

			DbgPrintEx(0, 0, "[JCcheats]this sizeofimage in ulong64 is %I64u	 \n", (ULONG64)pEntry->SizeOfImage);

			//PVOID tmpadd = MmGetSystemRoutineAddress(&pEntry->);
			//DbgPrintEx(0, 0, "[JCcheats]this base address of this particular dll/exe is %p	 \n", (void *)tmpadd);

			if (RtlCompareUnicodeString(&(pEntry->FullDllName),&module_name, TRUE) == NULL)
			{
				DbgPrintEx(0, 0, "[JCcheats]dll found inside PLIST_ENTRY \n");
				PVOID baseAddr = (PVOID)pEntry->DllBase;
				KeUnstackDetachProcess(&state);
				return baseAddr;

			}
			i++;
		}


	DbgPrintEx(0, 0, "[JCcheats]Rip no process found\n");
	KeUnstackDetachProcess(&state);
	return NULL;


}

bool read_kernel_memory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size)
{
	if (!address || !buffer || !size)
		return false;

	
	SIZE_T bytes = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;
	PsLookupProcessByProcessId((HANDLE)pid, &process);
	status = MmCopyVirtualMemory(process, (void*)address, (PEPROCESS)PsGetCurrentProcess(), (void*)buffer, size, KernelMode, &bytes);

	if (!NT_SUCCESS(status))
	{
		return false;
	}
	else
	{
		return true;
	}

}

bool write_kernel_memory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size)
{
	if (!address || !buffer || !size)
		return false;

	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;
	PsLookupProcessByProcessId((HANDLE)pid, &process);

	KAPC_STATE state;
	KeStackAttachProcess((PEPROCESS)process, &state);

	MEMORY_BASIC_INFORMATION info;

	status = ZwQueryVirtualMemory(ZwCurrentProcess(), (PVOID)address, MemoryBasicInformation, &info, sizeof(info), NULL);
	if (!NT_SUCCESS(status))
	{
		KeUnstackDetachProcess(&state);
		return false;
	}

	if (((uintptr_t)info.BaseAddress + info.RegionSize) < (address + size))
	{
		KeUnstackDetachProcess(&state);
		return false;
	}

	if (!(info.State & MEM_COMMIT) || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
	{
		KeUnstackDetachProcess(&state);
		return false;
	}


	if ((info.Protect & PAGE_EXECUTE_READWRITE) || (info.Protect & PAGE_EXECUTE_WRITECOPY) || (info.Protect & PAGE_READWRITE) || (info.Protect & PAGE_WRITECOPY))
	{
		RtlCopyMemory((void*)address, buffer, size);
	}

	KeUnstackDetachProcess(&state);
	return true;
}

